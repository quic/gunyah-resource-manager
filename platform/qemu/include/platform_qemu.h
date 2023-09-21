// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

RM_PADDED(typedef struct boot_env_gic_phys_range_s {
	paddr_t base;
	count_t count;
} boot_env_gic_phys_range_t)

RM_PADDED(struct platform_env_data_s {
	paddr_t gicd_base;

	size_t			  gicr_stride;
	count_t			  gicr_ranges_count;
	boot_env_gic_phys_range_t gicr_ranges[2];
})
