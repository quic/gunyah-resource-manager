// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <limits.h>

#include <util.h>
#include <utils/bitmap.h>

#include <compiler.h>

#define BITMAP_SET_BIT(x) ((register_t)1U << (((x) % BITMAP_WORD_BITS)))
#define BITMAP_WORD(x)	  ((x) / BITMAP_WORD_BITS)
#define BITMAP_SIZE_ASSERT(bitmap, bit)                                        \
	assert((index_t)(compiler_sizeof_object(bitmap) /                      \
			 sizeof(register_t)) > BITMAP_WORD(bit))

bool
bitmap_isset(const register_t *bitmap, index_t bit)
{
	BITMAP_SIZE_ASSERT(bitmap, bit);

	index_t i = BITMAP_WORD(bit);

	return (bitmap[i] & BITMAP_SET_BIT(bit)) != 0U;
}

void
bitmap_set(register_t *bitmap, index_t bit)
{
	BITMAP_SIZE_ASSERT(bitmap, bit);

	index_t i = BITMAP_WORD(bit);

	bitmap[i] |= BITMAP_SET_BIT(bit);
}

void
bitmap_clear(register_t *bitmap, index_t bit)
{
	BITMAP_SIZE_ASSERT(bitmap, bit);

	index_t i = BITMAP_WORD(bit);

	bitmap[i] &= ~BITMAP_SET_BIT(bit);
}

void
bitmap_toggle(register_t *bitmap, index_t bit)
{
	BITMAP_SIZE_ASSERT(bitmap, bit);

	index_t i = BITMAP_WORD(bit);

	bitmap[i] ^= BITMAP_SET_BIT(bit);
}

bool
bitmap_ffs(const register_t *bitmap, index_t num_bits, index_t *bit)
{
	assert(num_bits > 0U);
	BITMAP_SIZE_ASSERT(bitmap, num_bits - 1U);

	bool result = false;
	BITMAP_FOREACH_SET_BEGIN(i, bitmap, num_bits)
		result = true;
		*bit   = i;
		break;
	BITMAP_FOREACH_SET_END

	return result;
}

bool
bitmap_ffc(const register_t *bitmap, index_t num_bits, index_t *bit)
{
	assert(num_bits > 0U);
	BITMAP_SIZE_ASSERT(bitmap, num_bits - 1U);

	bool result = false;
	BITMAP_FOREACH_CLEAR_BEGIN(i, bitmap, num_bits)
		result = true;
		*bit   = i;
		break;
	BITMAP_FOREACH_CLEAR_END

	return result;
}

register_t
bitmap_get_word(const register_t *bitmap, index_t word, count_t num_bits)
{
	register_t ret = bitmap[word];

	if (word == BITMAP_WORD(num_bits)) {
		// Mask out bits not included in bitmap.
		ret &= util_mask(num_bits % BITMAP_WORD_BITS);
	}

	return ret;
}

count_t
bitmap_popcount(const register_t *bitmap, count_t num_bits)
{
	count_t ret = 0U;

	assert(num_bits > 0U);
	BITMAP_SIZE_ASSERT(bitmap, num_bits - 1U);

	for (index_t i = 0U; i < BITMAP_NUM_WORDS(num_bits); i++) {
		register_t word = bitmap_get_word(bitmap, i, num_bits);
		if (word != 0U) {
			ret += compiler_popcount(word);
		}
	}

	return ret;
}

void
bitmap_copy(register_t *dst, const register_t *src, count_t num_bits)
{
	assert(num_bits > 0U);
	BITMAP_SIZE_ASSERT(dst, num_bits - 1U);
	BITMAP_SIZE_ASSERT(src, num_bits - 1U);

	for (index_t i = 0U; i < BITMAP_NUM_WORDS(num_bits); i++) {
		dst[i] = bitmap_get_word(src, i, num_bits);
	}
}

bool
bitmap_is_equal(const register_t *b1, const register_t *b2, count_t num_bits)
{
	bool ret = true;

	assert(num_bits > 0U);
	BITMAP_SIZE_ASSERT(b1, num_bits - 1U);
	BITMAP_SIZE_ASSERT(b2, num_bits - 1U);

	for (index_t i = 0U; i < BITMAP_NUM_WORDS(num_bits); i++) {
		register_t w1 = bitmap_get_word(b1, i, num_bits);
		register_t w2 = bitmap_get_word(b2, i, num_bits);
		if (w1 != w2) {
			ret = false;
			break;
		}
	}

	return ret;
}
