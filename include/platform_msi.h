// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_PLATFORM_MSI_H_
#define INCLUDE_PLATFORM_MSI_H_

typedef uint32_t platform_msi_device_id_t;
typedef uint32_t platform_msi_event_id_t;

#define PLATFORM_MSI_DEVICE_ID_INVALID 0xffffffffu

typedef struct platform_msi_device {
	platform_msi_device_id_t device_id;
	platform_msi_event_id_t	 max_event;
} platform_msi_device_t;

RM_PADDED(typedef struct platform_msi_controller {
	count_t		       num_devices;
	platform_msi_device_t *devices;
} platform_msi_controller_t)

bool
platform_has_msi_support(void);

count_t
platform_get_msi_ctrl_count(void);

const platform_msi_controller_t *
platform_get_msi_controller(index_t idx);

count_t
platform_get_msi_ctrl_device_count(const platform_msi_controller_t *ctrl);

platform_msi_device_id_t
platform_get_msi_ctrl_device_id(const platform_msi_controller_t *ctrl,
				index_t				 dev_idx);

#else
#error multiple include of platform_msi.h
#endif
