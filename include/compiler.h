// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_COMPILER_H_
#define INCLUDE_COMPILER_H_

#define compiler_clz(x)                                                        \
	(assert((x) != 0U), (index_t) _Generic((x),                            \
		 unsigned long long: __builtin_clzll,                          \
		 unsigned long: __builtin_clzl,                                \
		 unsigned int: __builtin_clz)(x))

#define compiler_ctz(x)                                                        \
	(assert((x) != 0U), (index_t) _Generic((x),                            \
		 unsigned long long: __builtin_ctzll,                          \
		 unsigned long: __builtin_ctzl,                                \
		 unsigned int: __builtin_ctz)(x))

#define compiler_clrsb(x)                                                      \
	(index_t) _Generic((x),                                                \
		long long: __builtin_clrsbll,                                  \
		long: __builtin_clrsbl,                                        \
		int: __builtin_clrsb)(x)

#define compiler_popcount(x)                                                   \
	(assert((x) != 0U), (index_t) _Generic((x),                            \
		 unsigned long long: __builtin_popcountll,                     \
		 unsigned long: __builtin_popcountl,                           \
		 unsigned int: __builtin_popcount)(x))

#define compiler_msb(x) (index_t)((sizeof(x) * 8U) - 1U - compiler_clz(x))

// Object sizes, for use in minimum buffer size assertions. These return
// (size_t)-1 if the size cannot be determined statically, so the assertion
// should become a no-op in that case. LLVM has an intrinsic for this, so
// the static determination can be made after inlining by LTO.
#define compiler_sizeof_object(ptr)    __builtin_object_size((ptr), 1)
#define compiler_sizeof_container(ptr) __builtin_object_size((ptr), 0)

#else

#error multiple include of compiler.h

#endif
