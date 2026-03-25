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

bool
platform_has_msi_support(void)
{
	return false;
}

count_t
platform_get_msi_ctrl_count(void)
{
	return 0U;
}

const platform_msi_controller_t *
platform_get_msi_controller(index_t idx)
{
	(void)idx;

	return NULL;
}

count_t
platform_get_msi_ctrl_device_count(const platform_msi_controller_t *ctrl)
{
	(void)ctrl;

	return 0U;
}

platform_msi_device_id_t
platform_get_msi_ctrl_device_id(const platform_msi_controller_t *ctrl,
				index_t				 dev_idx)
{
	(void)ctrl;
	(void)dev_idx;

	return PLATFORM_MSI_DEVICE_ID_INVALID;
}
