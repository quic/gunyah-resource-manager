// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <util.h>
#include <utils/dict.h>

#include <compiler.h>

#define TABLE_SHIFT   (4U)
#define TABLE_ENTRIES (1U << TABLE_SHIFT)

#define MAX_DEPTH (4U)

#if defined(VERBOSE) && VERBOSE
// #define DEBUG(...) printf(__VA_ARGS__)
#define DEBUG(...) (void)0
count_t dict_alloc_size = 0U;
#define ALLOC_LOG(s) dict_alloc_size += (s)
#define FREE_LOG(s)  dict_alloc_size -= (s)
#else
#define DEBUG(...)   (void)0
#define ALLOC_LOG(s) (void)0
#define FREE_LOG(s)  (void)(s)
#endif

typedef struct dict_table_s {
	count_t children; // count of all children
	uint8_t _res[4];

	void *data[TABLE_ENTRIES];
} dict_table_t;

struct dict_s {
	dict_key_t key_min;
	dict_key_t key_max;

	count_t depth;
	uint8_t _res[4];

	// dict_table_t *tables[];
};

dict_t *
dict_init(dict_key_t key_min, dict_key_t key_max)
{
	assert(key_max > key_min);
	assert(!util_add_overflows((key_max - key_min), 1U));

	dict_key_t key_num = (key_max - key_min) + 1U;
	count_t key_bits = (sizeof(key_num) * 8U) - compiler_clz(key_num - 1U);

	count_t depth = 1U;
	while (key_bits > TABLE_SHIFT) {
		depth	 = depth + 1U;
		key_bits = key_bits - TABLE_SHIFT;
	}
	assert(key_bits != 0U);
	count_t top_levels = (count_t)util_bit(key_bits);

	if (depth > MAX_DEPTH) {
		(void)printf("dict depth > %d\n", MAX_DEPTH);
		exit(1);
	}

	// Allocate dict with top-level tables contiguously
	static_assert(sizeof(dict_t) % sizeof(void *) == 0U,
		      "dict_t not aligned");
	size_t top_size =
		sizeof(dict_t) + (sizeof(dict_table_t *) * top_levels);
	dict_t *dict = calloc(1, top_size);
	if (dict == NULL) {
		goto out;
	}
	ALLOC_LOG(top_size);

	dict->depth = depth;

	dict->key_min = key_min;
	dict->key_max = key_max;
	DEBUG("new dict %p, depth %d, key_min %d, key_max %d\n", dict, depth,
	      key_min, key_max);

out:
	return dict;
}

bool
dict_contains(dict_t *dict, dict_key_t key)
{
	return dict_get(dict, key) != NULL;
}

void *
dict_get(dict_t *dict, dict_key_t key)
{
	void *ret = NULL;

	if ((key < dict->key_min) || (key > dict->key_max)) {
		goto out;
	}

	dict_key_t key_index = key - dict->key_min;

	// First tables follow the dict
	void **tables = (void **)(void *)&dict[1];

	count_t depth = dict->depth - 1U;

	do {
		index_t shift = depth * TABLE_SHIFT;

		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);
		void *entry = tables[level_index];

		if ((depth == 0U) || (entry == NULL)) {
			ret = entry;
			break;
		} else {
			dict_table_t *table = entry;
			tables		    = (void **)(void *)&table->data;
		}

		depth = depth - 1U;
	} while (true);

out:
	return ret;
}

dict_key_ret_t
dict_get_first_free_key_from(dict_t *dict, dict_key_t from)
{
	dict_key_ret_t ret;

	if ((from < dict->key_min) || (from > dict->key_max)) {
		ret.err = ERROR_ARGUMENT_INVALID;
		ret.key = 0U;
		goto out;
	}

	dict_key_t key_index = from - dict->key_min;
	dict_key_t index_max = dict->key_max - dict->key_min;

	void **tables = (void **)(void *)&dict[1];

	count_t depth = dict->depth - 1U;
	index_t shift = depth * TABLE_SHIFT;

	bool found = false;

	void *stack_tables[MAX_DEPTH - 1U] = { NULL };

	do {
		DEBUG("%d: shift %d, key_index %d\n", depth, shift, key_index);
		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);

		if (tables[level_index] == NULL) {
			found = true;
			break;
		}
		if (depth > 0U) {
			dict_table_t *table = tables[level_index];
			// Table is full ?
			if (table->children == util_bit(shift)) {
				// Skip the subtree
				key_index =
					key_index + (dict_key_t)util_bit(shift);
				// Align since initial key_index not aligned
				key_index = util_balign_down(
					key_index, (dict_key_t)util_bit(shift));
				if (key_index > index_max) {
					break;
				}
				continue;
			}

			// Go down a level
			depth		    = depth - 1U;
			shift		    = shift - TABLE_SHIFT;
			stack_tables[depth] = tables;

			tables = (void **)(void *)&table->data;
		} else {
			while (level_index == (TABLE_ENTRIES - 1U)) {
				depth = depth + 1U;
				shift = shift + TABLE_SHIFT;
				if (depth == dict->depth) {
					goto end_iter;
				} else {
					tables	    = stack_tables[depth - 1U];
					level_index = (key_index >> shift) &
						      (TABLE_ENTRIES - 1U);
				}
			}
			key_index = key_index + 1U;
			if (key_index > index_max) {
				break;
			}
		}
	} while (true);

end_iter:
	if (found) {
		ret.err = OK;
		ret.key = dict->key_min + key_index;
		assert(ret.key <= dict->key_max);
	} else {
		ret.err = ERROR_NORESOURCES;
		ret.key = 0U;
	}

out:
	return ret;
}

dict_key_ret_t
dict_get_first_free_key(dict_t *dict)
{
	return dict_get_first_free_key_from(dict, dict->key_min);
}

error_t
dict_add(dict_t *dict, dict_key_t key, void *data)
{
	error_t ret;

	if ((key < dict->key_min) || (key > dict->key_max)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}
	if (data == NULL) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	dict_key_t key_index = key - dict->key_min;

	void **tables = (void **)(void *)&dict[1];

	count_t depth = dict->depth - 1U;
	index_t shift = depth * TABLE_SHIFT;

	void *stack_tables[MAX_DEPTH - 1U] = { NULL };

	do {
		DEBUG("%d: shift %d, key_index %d\n", depth, shift, key_index);
		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);

		if (tables[level_index] == NULL) {
			if (depth > 0U) {
				dict_table_t *table = calloc(1, sizeof(*table));
				ALLOC_LOG(sizeof(*table));
				DEBUG("alloc table %p\n", table);
				if (table == NULL) {
					ret = ERROR_NOMEM;
					goto out;
				}
				tables[level_index] = table;
			} else {
				// Insert the entry
				tables[level_index] = data;

				depth = depth + 1U;
				while (depth < dict->depth) {
					shift	    = shift + TABLE_SHIFT;
					level_index = (key_index >> shift) &
						      (TABLE_ENTRIES - 1U);
					tables = stack_tables[depth - 1U];
					dict_table_t *table =
						tables[level_index];

					table->children += 1U;
					DEBUG("table %p, children = %d\n",
					      table, table->children);
					DEBUG("%d <= %d\n", table->children,
					      (count_t)util_bit(shift));
					assert(table->children <=
					       util_bit(shift));
					depth = depth + 1U;
				}
				ret = OK;
				break;
			}
		} else if (depth > 0U) {
			dict_table_t *table = tables[level_index];
			// Table is full ?
			if (table->children == util_bit(shift)) {
				ret = ERROR_DENIED;
				goto out;
			}

			// Go down a level
			depth		    = depth - 1U;
			shift		    = shift - TABLE_SHIFT;
			stack_tables[depth] = tables;

			tables = (void **)(void *)&table->data;
		} else {
			ret = ERROR_DENIED;
			break;
		}
	} while (true);

out:
	return ret;
}

error_t
dict_remove(dict_t *dict, dict_key_t key, void **data)
{
	error_t ret;

	if ((key < dict->key_min) || (key > dict->key_max)) {
		ret = ERROR_ARGUMENT_INVALID;
		goto out;
	}

	dict_key_t key_index = key - dict->key_min;

	// First tables follow the dict
	void **tables = (void **)(void *)&dict[1];

	count_t depth = dict->depth - 1U;
	index_t shift = depth * TABLE_SHIFT;

	void *stack_tables[MAX_DEPTH - 1U] = { NULL };

	do {
		DEBUG("%d: shift %d, key_index %d\n", depth, shift, key_index);
		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);

		if (tables[level_index] == NULL) {
			ret = ERROR_NORESOURCES;
			break;
		}
		if (depth == 0U) {
			if (data != NULL) {
				*data = tables[level_index];
			}
			tables[level_index] = NULL;

			depth = depth + 1U;
			while (depth < dict->depth) {
				shift	    = shift + TABLE_SHIFT;
				level_index = (key_index >> shift) &
					      (TABLE_ENTRIES - 1U);
				tables		    = stack_tables[depth - 1U];
				dict_table_t *table = tables[level_index];

				assert(table->children > 0U);
				table->children -= 1U;
				DEBUG("table %p, children = %d\n", table,
				      table->children);
				DEBUG("%d <= %d\n", table->children,
				      (count_t)util_bit(shift));
				if (table->children == 0U) {
					tables[level_index] = NULL;
					DEBUG("free table %p\n", table);
					free(table);
					FREE_LOG(sizeof(*table));
					table = NULL;
				}

				depth = depth + 1U;
			}

			ret = OK;
			break;
		} else {
			dict_table_t *table = tables[level_index];

			// Go down a level
			depth		    = depth - 1U;
			shift		    = shift - TABLE_SHIFT;
			stack_tables[depth] = tables;
			tables		    = (void **)(void *)&table->data;
		}
	} while (true);

out:
	return ret;
}

void
dict_deinit(dict_t *dict)
{
	dict_key_t key_index = 0U;
	dict_key_t index_max = dict->key_max - dict->key_min;

	void **tables = (void **)(void *)&dict[1];

	count_t depth	  = dict->depth - 1U;
	count_t depth_top = depth;
	index_t shift	  = depth * TABLE_SHIFT;

	void *stack_tables[MAX_DEPTH - 1U] = { NULL };

	if (depth_top == 0U) {
		goto end_iter;
	}

	do {
		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);
		DEBUG("%d: %d: shift %d, key_index %d\n", depth, level_index,
		      shift, key_index);

		if ((tables[level_index] != NULL) && (depth > 1U)) {
			dict_table_t *table = tables[level_index];

			// Go down a level
			depth		    = depth - 1U;
			shift		    = shift - TABLE_SHIFT;
			stack_tables[depth] = tables;

			tables = (void **)(void *)&table->data;
		} else {
			dict_table_t *table = tables[level_index];
			if (table != NULL) {
				DEBUG("%d: free table %p\n", depth, table);
				free(table);
				FREE_LOG(sizeof(*table));
				tables[level_index] = NULL;
			}

			dict_key_t key_next =
				key_index + (dict_key_t)util_bit(shift);

			while (level_index == (TABLE_ENTRIES - 1U)) {
				if (depth == depth_top) {
					break;
				}

				depth	    = depth + 1U;
				shift	    = shift + TABLE_SHIFT;
				level_index = (key_index >> shift) &
					      (TABLE_ENTRIES - 1U);
				tables = stack_tables[depth - 1U];

				table = tables[level_index];
				assert(table != NULL);
				DEBUG("%d: up free table %p\n", depth, table);
				free(table);
				FREE_LOG(sizeof(*table));
				tables[level_index] = NULL;
			}

			if (key_next > index_max) {
				break;
			}
			key_index = key_next;
		}
	} while (true);

	while (depth < depth_top) {
		depth		    = depth + 1U;
		shift		    = shift + TABLE_SHIFT;
		index_t level_index = (key_index >> shift) &
				      (TABLE_ENTRIES - 1U);
		tables		    = stack_tables[depth - 1U];
		dict_table_t *table = tables[level_index];
		assert(table != NULL);
		DEBUG("free table %p\n", table);
		free(table);
		FREE_LOG(sizeof(*table));
	}

end_iter:
	depth = 1U;

	dict_key_t key_num = (dict->key_max + 1U) - dict->key_min;
	count_t key_bits = (sizeof(key_num) * 8U) - compiler_clz(key_num - 1U);

	while (key_bits > TABLE_SHIFT) {
		depth	 = depth + 1U;
		key_bits = key_bits - TABLE_SHIFT;
	}
	assert(key_bits != 0U);
	count_t top_levels = (count_t)util_bit(key_bits);

	size_t top_size =
		sizeof(dict_t) + (sizeof(dict_table_t *) * top_levels);
	free(dict);
	FREE_LOG(top_size);
}

dict_key_t
dict_get_min_key(dict_t *dict)
{
	return dict->key_min;
}

dict_key_t
dict_get_max_key(dict_t *dict)
{
	return dict->key_max;
}
