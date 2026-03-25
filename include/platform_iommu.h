// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI
error_t
platform_iommu_init(vm_config_t *vmcfg);

error_t
platform_iommu_vpci_add(vm_config_t *vmcfg);

const stream_id_range_t *
platform_iommu_get_hlos_stream_id_ranges(index_t  iommu_idx,
					 count_t *num_ranges);
#endif
