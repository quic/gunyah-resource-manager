// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

// We are able to parse the VIC configuration from the DT
#define PLATFORM_VIC_DEFAULT_ADDR false

RM_PADDED(typedef struct platform_virtio_iommu_s {
	cap_id_t iommu_cap;
} platform_virtio_iommu_t)

RM_PADDED(typedef struct platform_vm_config_s {
	index_t primary_vm_index;
	// vector of platform_virtio_iommu_t
	vector_t *virtio_iommus;
} platform_vm_config_t)

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s vm_config_parser_data_t;

error_t
platform_vm_config_create_vdevices(vm_config_t		   *vmcfg,
				   vm_config_parser_data_t *data);

error_t
platform_vm_config_hlos_vdevices_setup(vm_config_t *vmcfg);

#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI
error_t
platform_add_vpci_devices(vm_config_t *vmcfg);
#endif
