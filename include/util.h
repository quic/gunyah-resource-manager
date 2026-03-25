// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

// Miscellaneous utility macros.
//
// These all have simple definitions - no compiler builtins or other language
// extensions. Look in compiler.h for those.

#ifndef INCLUDE_UTIL_H_
#define INCLUDE_UTIL_H_

#include <stddef.h>

#define util_bit(b)  ((uintmax_t)1U << (b))
#define util_sbit(b) ((intmax_t)1 << (b))
#define util_mask(n) (util_bit(n) - 1U)

#define util_max(x, y) (((x) > (y)) ? (x) : (y))
#define util_min(x, y) (((x) < (y)) ? (x) : (y))

// Arithmetic predicates with intent that is not obvious when open-coded
#define util_is_p2_or_zero(x) (((x) & ((x) - 1U)) == 0U)
#define util_is_p2(x)	      (((x) != 0U) && util_is_p2_or_zero(x))
#define util_is_baligned(x, a)                                                 \
	(assert(util_is_p2(a)), (((x) & ((a) - 1U)) == 0U))
#define util_is_p2aligned(x, b)	 (((x) & (util_bit(b) - 1U)) == 0U)
#define util_add_overflows(a, b) ((a) > ~(__typeof__((a) + (b)))(b))

#define util_mult_integer_overflows(a, b)                                      \
	(bool)_Generic((a) * (b),                                              \
		uint32_t: (((uint64_t)(a) * (b)) > UINT32_MAX),                \
		uint64_t: (((__uint128_t)(a) * (b)) > UINT64_MAX))

// Align up or down to bytes (which must be a power of two)
#define util_balign_down(x, a)                                                 \
	(assert(util_is_p2(a)), (x) & ~((__typeof__(x))(a) - 1U))
#define util_balign_up(x, a) util_balign_down((x) + ((a) - 1U), (a))

// Align up or down to a power-of-two size (in bits)
#define util_p2align_down(x, b)                                                \
	(assert((sizeof(x) * 8U) > (b)), (((x) >> (b)) << (b)))
#define util_p2align_up(x, b) util_p2align_down((x) + util_bit(b) - 1U, (b))

// Return the number of elements in an array.
#define util_array_size(a) (sizeof(a) / sizeof((a)[0]))

// Generate an identifier that can be declared inside a macro without
// shadowing anything else declared in the same file, given a base name to
// disambiguate uses within one macro expansion. Generally the name should be
// prefixed with the name of the macro it's being used in.
//
// Note that this should only ever be used as a macro parameter; otherwise
// it is difficult to determine what identifier it expanded to.
#define util_cpp_unique_ident(name) util_cpp_paste_expanded(name, __LINE__)

// Paste two tokens together, after macro-expansion of the arguments.
#define util_cpp_paste_expanded(name, suffix) util_cpp_paste(name, suffix)

// Paste two tokens together, before macro-expansion of the arguments.
//
// This is only really useful in util_cpp_paste_expanded(). In any other macro
// definition, use ## directly, which is equivalent and more concise.
#define util_cpp_paste(name, suffix) name##suffix

// memscpy implementation
extern size_t
memscpy(void *s1, size_t s1_size, const void *s2, size_t s2_size);

// Allocate a contiguous range of pages from the heap.
//
// The size must be a multiple of PAGE_SIZE. The returned memory is always zero
// initialised.
void *
util_alloc_pages(size_t size);

// Free memory allocated with util_alloc_pages().
void
util_free_pages(void *ptr, size_t size);

#else

#error multiple include of util.h

#endif
