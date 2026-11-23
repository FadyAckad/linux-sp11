// SPDX-License-Identifier: GPL-2.0-only
/*
 * TPM 2.0 through Microsoft's secure application on Qualcomm SoCs
 *
 * Snapdragon X laptops sold with Windows carry a TPM 2.0 (Microsoft Pluton)
 * that their ACPI TPM2 table describes with start method 14 and a command
 * response buffer (CRB, TCG PC Client Platform TPM Profile). The QSEE
 * application qcom.tz.mssecapp returns the address of that buffer and starts
 * each command in it; Windows talks to the TPM this way until its secure
 * processor driver is up. The requests are the ones Windows' drivers make
 * (tpm.sys and Qualcomm's QcTrEE.sys).
 */

#include <linux/auxiliary_bus.h>
#include <linux/firmware/qcom/qcom_qseecom.h>
#include <linux/firmware/qcom/qcom_tzmem.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "tpm.h"

#define MSSECAPP_CMD_START	0x4003	/* run the command in the CRB */
#define MSSECAPP_CMD_GET_CRB	0x4004
#define MSSECAPP_CMD_VERSION	0x4007

#define MSSECAPP_VERSION	0x00010000
#define MSSECAPP_CRB_MAX_SIZE	0x3000
#define MSSECAPP_RSP_OFFSET	8	/* of the response in a request buffer */

#define MSSECAPP_START_INVOKE	BIT(0)
#define MSSECAPP_POLL_US	100
#define MSSECAPP_TIMEOUT_US	(2 * USEC_PER_SEC)

struct mssecapp_rsp_version {
	__le32 status;
	__le32 command_id;
	__le32 version;
} __packed;

struct mssecapp_rsp_crb {
	__le32 command_id;
	__le32 size;
	__le64 phys;
	__le32 status;
	__le32 reserved;
} __packed;

struct mssecapp_rsp_start {
	__le32 command_id;
	__le32 status;
} __packed;

/* The CRB control area; the command and response buffers follow it. */
struct mssecapp_crb {
	u32 ctrl_req;
	u32 ctrl_sts;
	u32 ctrl_cancel;
	u32 ctrl_start;
	u32 ctrl_int_enable;
	u32 ctrl_int_sts;
	u32 ctrl_cmd_size;
	u32 ctrl_cmd_pa_low;
	u32 ctrl_cmd_pa_high;
	u32 ctrl_rsp_size;
	u32 ctrl_rsp_pa_low;
	u32 ctrl_rsp_pa_high;
} __packed;

struct tpm_mssecapp {
	struct qseecom_client *client;
	struct qcom_tzmem_pool *mempool;
	struct mssecapp_crb __iomem *regs;
	void __iomem *cmd;
	void __iomem *rsp;
	u32 cmd_size;
	u32 rsp_size;
	struct tpm_chip *chip;
	struct work_struct register_work;
	bool registered;
};

/* One request: its command ID at the start of a TZ buffer, the response after. */
static int mssecapp_request(struct tpm_mssecapp *priv, u32 command_id,
			    void *rsp, size_t rsp_size)
{
	size_t size = MSSECAPP_RSP_OFFSET + rsp_size;
	int ret;

	void *buf __free(qcom_tzmem) = qcom_tzmem_alloc(priv->mempool, size,
							GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, size);
	*(__le32 *)buf = cpu_to_le32(command_id);

	ret = qcom_qseecom_app_send(priv->client, buf, sizeof(__le32),
				    buf + MSSECAPP_RSP_OFFSET, rsp_size);
	if (ret)
		return ret;

	memcpy(rsp, buf + MSSECAPP_RSP_OFFSET, rsp_size);
	return 0;
}

static int tpm_mssecapp_send(struct tpm_chip *chip, u8 *buf, size_t bufsiz,
			     size_t cmd_len)
{
	struct tpm_mssecapp *priv = dev_get_drvdata(&chip->dev);
	struct mssecapp_rsp_start rsp;
	u32 sts, start, len;
	int ret;

	if (cmd_len > priv->cmd_size)
		return -E2BIG;

	memcpy_toio(priv->cmd, buf, cmd_len);
	/* The command must be in memory before the secure world reads it. */
	wmb();

	/* As Windows' driver does, start a command only with a clear status. */
	sts = ioread32(&priv->regs->ctrl_sts);
	if (sts) {
		dev_err(&chip->dev, "CRB status %#x\n", sts);
		return -EIO;
	}

	iowrite32(MSSECAPP_START_INVOKE, &priv->regs->ctrl_start);

	ret = mssecapp_request(priv, MSSECAPP_CMD_START, &rsp, sizeof(rsp));
	if (ret)
		return ret;

	if (le32_to_cpu(rsp.status)) {
		dev_err(&chip->dev, "start request failed: status %#x\n",
			le32_to_cpu(rsp.status));
		return -EIO;
	}

	/* The request returns once the TPM is done; the CRB confirms it. */
	ret = readl_poll_timeout(&priv->regs->ctrl_start, start,
				 !(start & MSSECAPP_START_INVOKE),
				 MSSECAPP_POLL_US, MSSECAPP_TIMEOUT_US);
	if (ret)
		return ret;

	memcpy_fromio(buf, priv->rsp, TPM_HEADER_SIZE);
	len = be32_to_cpup((__be32 *)&buf[2]);
	if (len < TPM_HEADER_SIZE || len > priv->rsp_size || len > bufsiz)
		return -EIO;

	memcpy_fromio(buf + TPM_HEADER_SIZE, priv->rsp + TPM_HEADER_SIZE,
		      len - TPM_HEADER_SIZE);
	return len;
}

static const struct tpm_class_ops tpm_mssecapp_ops = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.send = tpm_mssecapp_send,
};

/*
 * The TPM's first self test after the firmware takes seconds, and the probe
 * runs where the kernel's start waits for it, so the chip is registered from
 * a work item.
 */
static void tpm_mssecapp_register(struct work_struct *work)
{
	struct tpm_mssecapp *priv = container_of(work, struct tpm_mssecapp,
						 register_work);
	int ret;

	ret = tpm2_probe(priv->chip);
	if (!ret)
		ret = tpm_chip_register(priv->chip);
	if (ret) {
		dev_err(priv->chip->dev.parent, "TPM not registered: %d\n", ret);
		return;
	}

	priv->registered = true;
}

/* A buffer the control area names, which must lie after the control area. */
static void __iomem *mssecapp_buffer(void __iomem *base, phys_addr_t phys,
				     u32 size, u64 pa, u32 len)
{
	if (pa < phys + sizeof(struct mssecapp_crb) || !len ||
	    pa + len > phys + size)
		return NULL;

	return base + (pa - phys);
}

static int tpm_mssecapp_probe(struct auxiliary_device *aux_dev,
			      const struct auxiliary_device_id *aux_dev_id)
{
	struct qcom_tzmem_pool_config pool_config = {
		.initial_size = SZ_4K,
		.policy = QCOM_TZMEM_POLICY_MULTIPLIER,
		.increment = 2,
		.max_size = SZ_16K,
	};
	struct device *dev = &aux_dev->dev;
	struct mssecapp_rsp_version ver;
	struct mssecapp_rsp_crb crb;
	struct tpm_mssecapp *priv;
	struct tpm_chip *chip;
	void __iomem *base;
	u64 cmd_pa, rsp_pa;
	phys_addr_t phys;
	u32 size;
	int ret;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->client = container_of(aux_dev, struct qseecom_client, aux_dev);

	priv->mempool = devm_qcom_tzmem_pool_new(dev, &pool_config);
	if (IS_ERR(priv->mempool))
		return PTR_ERR(priv->mempool);

	ret = mssecapp_request(priv, MSSECAPP_CMD_VERSION, &ver, sizeof(ver));
	if (ret)
		return dev_err_probe(dev, ret, "version request failed\n");

	if (le32_to_cpu(ver.status) ||
	    le32_to_cpu(ver.version) != MSSECAPP_VERSION)
		return dev_err_probe(dev, -ENODEV,
				     "unsupported interface: status %#x, version %#x\n",
				     le32_to_cpu(ver.status),
				     le32_to_cpu(ver.version));

	ret = mssecapp_request(priv, MSSECAPP_CMD_GET_CRB, &crb, sizeof(crb));
	if (ret)
		return dev_err_probe(dev, ret, "buffer request failed\n");

	if (le32_to_cpu(crb.status))
		return dev_err_probe(dev, -ENODEV, "no buffer: status %#x\n",
				     le32_to_cpu(crb.status));

	phys = le64_to_cpu(crb.phys);
	size = le32_to_cpu(crb.size);
	if (size <= sizeof(struct mssecapp_crb) ||
	    size > MSSECAPP_CRB_MAX_SIZE ||
	    region_intersects(phys, size, IORESOURCE_SYSTEM_RAM,
			      IORES_DESC_NONE) != REGION_DISJOINT)
		return dev_err_probe(dev, -EINVAL,
				     "unusable buffer at %pa, size %#x\n",
				     &phys, size);

	base = devm_ioremap(dev, phys, size);
	if (!base)
		return -ENOMEM;

	priv->regs = base;
	priv->cmd_size = ioread32(&priv->regs->ctrl_cmd_size);
	priv->rsp_size = ioread32(&priv->regs->ctrl_rsp_size);
	cmd_pa = (u64)ioread32(&priv->regs->ctrl_cmd_pa_high) << 32 |
		 ioread32(&priv->regs->ctrl_cmd_pa_low);
	rsp_pa = (u64)ioread32(&priv->regs->ctrl_rsp_pa_high) << 32 |
		 ioread32(&priv->regs->ctrl_rsp_pa_low);

	priv->cmd = mssecapp_buffer(base, phys, size, cmd_pa, priv->cmd_size);
	priv->rsp = mssecapp_buffer(base, phys, size, rsp_pa, priv->rsp_size);
	if (!priv->cmd || !priv->rsp || priv->rsp_size < TPM_HEADER_SIZE)
		return dev_err_probe(dev, -EINVAL,
				     "buffers outside the area: command %#llx+%#x, response %#llx+%#x\n",
				     cmd_pa, priv->cmd_size, rsp_pa,
				     priv->rsp_size);

	chip = tpmm_chip_alloc(dev, &tpm_mssecapp_ops);
	if (IS_ERR(chip))
		return PTR_ERR(chip);

	dev_set_drvdata(&chip->dev, priv);
	chip->flags |= TPM_CHIP_FLAG_SYNC;
	priv->chip = chip;

	INIT_WORK(&priv->register_work, tpm_mssecapp_register);
	queue_work(system_dfl_long_wq, &priv->register_work);

	return 0;
}

static void tpm_mssecapp_remove(struct auxiliary_device *aux_dev)
{
	struct tpm_chip *chip = auxiliary_get_drvdata(aux_dev);
	struct tpm_mssecapp *priv = dev_get_drvdata(&chip->dev);

	cancel_work_sync(&priv->register_work);
	if (priv->registered)
		tpm_chip_unregister(chip);
}

static const struct auxiliary_device_id tpm_mssecapp_id_table[] = {
	{ .name = "qcom_qseecom.mssecapp" },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, tpm_mssecapp_id_table);

static struct auxiliary_driver tpm_mssecapp_driver = {
	.probe = tpm_mssecapp_probe,
	.remove = tpm_mssecapp_remove,
	.id_table = tpm_mssecapp_id_table,
	.driver = {
		.name = "tpm_qcom_mssecapp",
	},
};
module_auxiliary_driver(tpm_mssecapp_driver);

MODULE_DESCRIPTION("TPM 2.0 through the Qualcomm QSEE application qcom.tz.mssecapp");
MODULE_LICENSE("GPL");
