// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <rm_types.h>
#include <util.h>

#include <platform_iommu.h>

#if defined(PLATFORM_HLOS_NEEDS_VPCI) && PLATFORM_HLOS_NEEDS_VPCI

// These should match the ranges in the dt. The way the data is organised and
// the below function may need to changed if the dt changes.
static const stream_id_range_t stream_id_ranges[] = {
	{ .id_start = 0x200U, .count = 0x100 },
	{ .id_start = 0x700U, .count = 0x100 },
};

const stream_id_range_t *
platform_iommu_get_hlos_stream_id_ranges(index_t iommu_idx, count_t *num_ranges)
{
	const stream_id_range_t *ret;

	if (iommu_idx == 0U) {
		*num_ranges = util_array_size(stream_id_ranges);
		ret	    = stream_id_ranges;
	} else {
		*num_ranges = 0U;
		ret	    = NULL;
	}

	return ret;
}
#endif
