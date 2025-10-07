// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_COMPILER_H_
#define INCLUDE_COMPILER_H_

// clang-format off
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

#define compiler_popcount(x) (assert((x) != 0U), (index_t)_Generic(	       \
	(x),								       \
	unsigned long long: __builtin_popcountll,			       \
	unsigned long: __builtin_popcountl,				       \
	unsigned int: __builtin_popcount)(x))
// clang-format on

#else

#error multiple include of compiler.h

#endif
