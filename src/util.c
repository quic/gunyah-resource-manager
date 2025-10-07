// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <string.h>

#include <util.h>

size_t
memscpy(void *s1, size_t s1_size, const void *s2, size_t s2_size)
{
	size_t copy_size = util_min(s1_size, s2_size);
	if (copy_size != (size_t)0) {
		(void)memcpy(s1, s2, copy_size);
	}
	return copy_size;
}
