// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <compiler.h>
#include <errno.h>
#include <log.h>
#include <platform_msi.h>

static platform_msi_device_t msi_ctrl0_devices[] = {
	// PCIe RC0
	// SMMU test engines
	{ .device_id = 0xF0U, .max_event = 32 },
	{ .device_id = 0xF1U, .max_event = 32 },
	{ .device_id = 0x200U, .max_event = 32 },
	{ .device_id = 0x204U, .max_event = 32 },
	{ .device_id = 0x600U, .max_event = 32 },
	{ .device_id = 0x607U, .max_event = 32 },
	{ .device_id = 0x700U, .max_event = 32 },
	{ .device_id = 0x703U, .max_event = 32 },
	{ .device_id = 0x800U, .max_event = 32 },
	{ .device_id = 0x801U, .max_event = 32 },
	// AHCI
	{ .device_id = 0xF8U, .max_event = 32 },
	{ .device_id = 0x100U, .max_event = 32 },
	{ .device_id = 0x500U, .max_event = 32 },
};

// For the moment we use the wired interrupts for the RC0
// SMMUv3. We still have to init these unused structs.
// If these are not initialized the vITS throws an assert.
// The platform apparently uses these for another PCIE RC
// and dedicated SMMUv3 ITSs for those. The exact mapping is
// still unclear.
static platform_msi_device_t msi_ctrl1_devices[] = {
	{ .device_id = 0x0U, .max_event = 32 },
};

static platform_msi_device_t msi_ctrl2_devices[] = {
	{ .device_id = 0x0U, .max_event = 32 },
};

static platform_msi_device_t msi_ctrl3_devices[] = {
	{ .device_id = 0x0U, .max_event = 32 },
};

static const platform_msi_controller_t msi_controllers[] = {
	[0] = { .num_devices = (count_t)util_array_size(msi_ctrl0_devices),
		.devices     = msi_ctrl0_devices },
	[1] = { .num_devices = (count_t)util_array_size(msi_ctrl1_devices),
		.devices     = msi_ctrl1_devices },
	[2] = { .num_devices = (count_t)util_array_size(msi_ctrl2_devices),
		.devices     = msi_ctrl2_devices },
	[3] = { .num_devices = (count_t)util_array_size(msi_ctrl3_devices),
		.devices     = msi_ctrl3_devices },
};

bool
platform_has_msi_support(void)
{
	return true;
}

count_t
platform_get_msi_ctrl_count(void)
{
	return (count_t)util_array_size(msi_controllers);
}

const platform_msi_controller_t *
platform_get_msi_controller(index_t idx)
{
	const platform_msi_controller_t *controller = NULL;

	if (idx < util_array_size(msi_controllers)) {
		controller = &msi_controllers[idx];
	}

	return controller;
}

count_t
platform_get_msi_ctrl_device_count(const platform_msi_controller_t *ctrl)
{
	return ctrl->num_devices;
}

platform_msi_device_id_t
platform_get_msi_ctrl_device_id(const platform_msi_controller_t *ctrl,
				index_t				 dev_idx)
{
	platform_msi_device_id_t dev_id;

	if (dev_idx < platform_get_msi_ctrl_device_count(ctrl)) {
		dev_id = ctrl->devices[dev_idx].device_id;
	} else {
		dev_id = PLATFORM_MSI_DEVICE_ID_INVALID;
	}

	return dev_id;
}
