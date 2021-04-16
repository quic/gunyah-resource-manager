// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Miscellaneous utility macros.
//
// These all have simple definitions - no compiler builtins or other language
// extensions. Look in compiler.h for those.

#define util_bit(b)  ((uintmax_t)1U << (b))
#define util_sbit(b) ((intmax_t)1 << (b))
#define util_mask(n) (util_bit(n) - 1)

#define util_max(x, y) (((x) > (y)) ? (x) : (y))
#define util_min(x, y) (((x) < (y)) ? (x) : (y))

// Arithmetic predicates with intent that is not obvious when open-coded
#define util_is_p2_or_zero(x)	 (((x) & ((x)-1U)) == 0U)
#define util_is_p2(x)		 (((x) != 0U) && util_is_p2_or_zero(x))
#define util_is_baligned(x, a)	 (assert(util_is_p2(a)), (((x) & ((a)-1U)) == 0U))
#define util_is_p2aligned(x, b)	 (((x) & ~(util_bit(b) - 1)) == 0U)
#define util_add_overflows(a, b) ((a) > ~(b))

// Align up or down to bytes (which must be a power of two)
#define util_balign_down(x, a)                                                 \
	(assert(util_is_p2(a)), (x) & ~((__typeof__(x))(a)-1U))
#define util_balign_up(x, a) util_balign_down((x) + ((a)-1U), a)

// Align up or down to a power-of-two size (in bits)
#define util_p2align_down(x, b)                                                \
	(assert((sizeof(x) * 8) > (b)), (((x) >> (b)) << (b)))
#define util_p2align_up(x, b) util_p2align_down((x) + util_bit(b) - 1U, b)

// Return the number of elements in an array.
#define util_array_size(a) (sizeof(a) / sizeof((a)[0]))
