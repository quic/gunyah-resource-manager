// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef UTILS_BITMAP_H_
#define UTILS_BITMAP_H_

#define BITMAP_WORD_BITS    ((count_t)(sizeof(register_t) * (size_t)CHAR_BIT))
#define BITMAP_NUM_WORDS(x) (((x) + BITMAP_WORD_BITS - 1U) / BITMAP_WORD_BITS)
#define BITMAP_SIZE(x)	    (BITMAP_NUM_WORDS(x) * sizeof(register_t))

#define BITMAP_DECLARE(bits, name) register_t name[BITMAP_NUM_WORDS(bits)]

bool
bitmap_isset(const register_t *bitmap, index_t bit);

void
bitmap_set(register_t *bitmap, index_t bit);

void
bitmap_clear(register_t *bitmap, index_t bit);

void
bitmap_toggle(register_t *bitmap, index_t bit);

bool
bitmap_ffs(const register_t *bitmap, index_t num_bits, index_t *bit);

bool
bitmap_ffc(const register_t *bitmap, index_t num_bits, index_t *bit);

register_t
bitmap_get_word(const register_t *bitmap, index_t word, count_t num_bits);

count_t
bitmap_popcount(const register_t *bitmap, count_t num_bits);

void
bitmap_copy(register_t *dst, const register_t *src, count_t num_bits);

bool
bitmap_is_equal(const register_t *b1, const register_t *b2, count_t num_bits);

// Loop macros for iterating over bitmaps. Note that these are written
// to avoid using break statements, so the body provided by the caller
// can use a break or goto statement without breaking MISRA rule 15.4.
#define BITMAP__FOREACH_BEGIN(i, w, r, b, g, n)                                \
	{                                                                      \
		index_t	   w = 0U;                                             \
		register_t r = 0U;                                             \
		while (((r) != 0U) || (((w) * BITMAP_WORD_BITS) < (n))) {      \
			if ((r) == 0U) {                                       \
				(r) = g((b), (w), (n));                        \
				(w)++;                                         \
			}                                                      \
			if ((r) != 0U) {                                       \
				index_t i = compiler_ctz(r);                   \
				(r) &= ~(register_t)1U << (i);                 \
				(i) += (((w) - 1U) * BITMAP_WORD_BITS);

// clang-format off
#define BITMAP__FOREACH_END }}}
// clang-format on

#define BITMAP_FOREACH_SET_BEGIN(i, b, n)                                      \
	BITMAP__FOREACH_BEGIN(i, util_cpp_unique_ident(w),                     \
			      util_cpp_unique_ident(r), (b), bitmap_get_word,  \
			      (n))
#define BITMAP_FOREACH_SET_END BITMAP__FOREACH_END

#define BITMAP_FOREACH_CLEAR_BEGIN(i, b, n)                                    \
	BITMAP__FOREACH_BEGIN(i, util_cpp_unique_ident(w),                     \
			      util_cpp_unique_ident(r), (b), ~bitmap_get_word, \
			      (n))
#define BITMAP_FOREACH_CLEAR_END BITMAP__FOREACH_END

#else

#error multiple include of utils/bitmap.h

#endif
