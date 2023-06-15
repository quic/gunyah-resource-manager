// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// We are able to parse the VIC configuration from the DT
#define PLATFORM_VIC_DEFAULT_ADDR false

RM_PADDED(typedef struct platform_vm_config_s {
	index_t primary_vm_index;

	int ramfs_idx;

	vmaddr_t vgic_gicd_base;
	vmaddr_t vgic_gicr_base;
	vmaddr_t vgic_gicr_stride;
	uint32_t vgic_phandle;
	count_t	 vgic_addr_cells;
	count_t	 vgic_size_cells;
	bool	 vgic_patch_dt;
} platform_vm_config_t)

struct dtb_parser_data_s;
typedef struct dtb_parser_data_s vm_config_parser_data_t;

error_t
platform_vm_config_create_vdevices(vm_config_t		   *vmcfg,
				   vm_config_parser_data_t *data);

error_t
platform_vm_config_hlos_vdevices_setup(vm_config_t *vmcfg);
