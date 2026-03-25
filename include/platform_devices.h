// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_PLATFORM_DEVICES_H_
#define INCLUDE_PLATFORM_DEVICES_H_

RM_PADDED(typedef struct platform_device {
	resource_descriptor_t *mmios;
	resource_descriptor_t *irqs;
	resource_descriptor_t *iommu_eps;
	resource_descriptor_t *msi_eps;
	count_t		       num_mmios;
	count_t		       num_irqs;
	count_t		       num_iommu_eps;
	count_t		       num_msi_eps;
} platform_device_t)

count_t
platform_get_device_count(void);

const platform_device_t *
platform_get_device(index_t idx);

count_t
platform_get_device_all_res_count(const platform_device_t *device);

count_t
platform_get_device_res_count(const platform_device_t *device,
			      resource_descr_type_t    res_type);

const resource_descriptor_t *
platform_get_device_res(const platform_device_t *device, const index_t idx,
			resource_descr_type_t res_type);

bool
platform_is_device_mmio(paddr_t paddr);

bool
platform_is_device_irq(uint32_t irq);

#else
#error multiple inclujde of platform_devices.h
#endif
