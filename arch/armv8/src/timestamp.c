// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <stdint.h>
#include <stdlib.h>

uint64_t
read_timestamp(void);

uint64_t
read_timestamp(void)
{
	uint64_t ret;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(ret));
	return ret;
}
