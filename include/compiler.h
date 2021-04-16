// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// clang-format off
#define compiler_ffs(x) (index_t)_Generic(				       \
	(x),								       \
	long long: __builtin_ffsll(x),					       \
	unsigned long long: __builtin_ffsll((long long)(x)),		       \
	long: __builtin_ffsl(x),					       \
	unsigned long: __builtin_ffsl((long)(x)),			       \
	int: __builtin_ffs(x),						       \
	unsigned int: __builtin_ffs((int)(x)))

#define compiler_clz(x) (assert((x) != 0U), (index_t)_Generic(		       \
	(x),								       \
	unsigned long long: __builtin_clzll,				       \
	unsigned long: __builtin_clzl,				       \
	unsigned int: __builtin_clz)(x))

#define compiler_ctz(x) (assert((x) != 0U), (index_t)_Generic(		       \
	(x),								       \
	unsigned long long: __builtin_ctzll,				       \
	unsigned long: __builtin_ctzl,				       \
	unsigned int: __builtin_ctz)(x))

#define compiler_clrsb(x) (index_t)_Generic(				       \
	(x), long long: __builtin_clrsbll,				       \
	long: __builtin_clrsbl,					       \
	int: __builtin_clrsb)(x)
// clang-format on
