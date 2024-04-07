/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021-2023, NVIDIA CORPORATION & AFFILIATES.
 */

#include <config.h>
#include <initcall.h>
#include <kernel/boot.h>
#include <stdlib.h>
#include <io.h>
#include <drivers/tegra/tegra_fuse.h>
#include <tegra_driver_fuse.h>
#include <tegra_driver_srv_intf.h>

#define FUSE_BOOT_SECURITY_INFO_0	0x268

static vaddr_t fuse_va_base = 0;
static fuse_ecid_t fuse_ecid;
static uint64_t fuse_ecid_64bit = 0;
static uint8_t fuse_sn[FUSE_SN_SIZE];

static fuse_ecid_t* fuse_get_ecid(void)
{
	return &fuse_ecid;
}

static TEE_Result fuse_get_64bit_ecid(uint64_t *val)
{
	if (val == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (fuse_ecid_64bit == 0)
		return TEE_ERROR_NOT_SUPPORTED;

	*val = fuse_ecid_64bit;
	return TEE_SUCCESS;
}

static TEE_Result fuse_get_bsi(uint32_t *val)
{
	if (val == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	*val = io_read32(fuse_va_base + FUSE_BOOT_SECURITY_INFO_0);
	return TEE_SUCCESS;
}

static TEE_Result fuse_get_sn(uint8_t **sn, uint32_t *size)
{
	if (sn == NULL || size == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	*sn = fuse_sn;
	*size = FUSE_SN_SIZE;
	return TEE_SUCCESS;
}

static TEE_Result tegra_fuse_init(void)
{
	TEE_Result rc = TEE_SUCCESS;
	tegra_drv_srv_intf_t *drv_srv_intf = NULL;
	size_t map_size = 0;
	uint32_t sn_size = FUSE_SN_SIZE;

	rc = tegra_fuse_map_regs(&fuse_va_base, &map_size);
	if (rc == TEE_SUCCESS) {
		rc = fuse_generate_ecid(fuse_va_base, &fuse_ecid, &fuse_ecid_64bit);
		if (rc != TEE_SUCCESS) {
			EMSG("Tegra fuse: generate ECID failed: 0x%x\n", rc);
			tegra_fuse_unmap_regs(fuse_va_base, map_size);
			return rc;
		}

		rc = fuse_generate_sn(fuse_va_base, fuse_sn, &sn_size);
		if (rc != TEE_SUCCESS) {
			EMSG("Tegra fuse: generate SN failed: 0x%x\n", rc);
			tegra_fuse_unmap_regs(fuse_va_base, map_size);
			return rc;
		}

		drv_srv_intf = tegra_drv_srv_intf_get();
		if (drv_srv_intf != NULL) {
			drv_srv_intf->get_ecid = fuse_get_ecid;
			drv_srv_intf->get_64bit_ecid = fuse_get_64bit_ecid;
			drv_srv_intf->get_bsi = fuse_get_bsi;
			drv_srv_intf->get_sn = fuse_get_sn;
		} else {
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}

	return rc;
}

service_init(tegra_fuse_init);
