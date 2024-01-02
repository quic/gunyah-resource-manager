// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

RM_PADDED(struct platform_vm_config_parser_data {
	index_t	 primary_vm_index;
	int	 ramfs_idx;
	vmaddr_t vgic_gicd_base;
	vmaddr_t vgic_gicr_base;
	vmaddr_t vgic_gicr_stride;
	uint32_t vgic_phandle;
	count_t	 vgic_addr_cells;
	count_t	 vgic_size_cells;
	bool	 vgic_patch_dt;
})

typedef struct platform_vm_config_parser_data platform_vm_config_parser_data_t;

rm_error_t
platform_alloc_parser_data(vm_config_parser_data_t *vd);

void
platform_free_parser_data(vm_config_parser_data_t *vd);
