// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdint.h>
#include <stdlib.h>

#include <rm_types.h>

#include <platform.h>

uint64_t
platform_timestamp(void)
{
	uint64_t ret;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(ret));
	return ret;
}
