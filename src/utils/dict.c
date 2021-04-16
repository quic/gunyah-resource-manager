// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <utils/dict.h>

#define INIT_CAPACITY	    (64)
#define CAPACITY_LIMITATION (1024)

dict_t *
dict_init()
{
	dict_t *ret = (dict_t *)malloc(sizeof(*ret));
	assert(ret != NULL);

	ret->capacity  = INIT_CAPACITY;
	size_t data_sz = sizeof(ret->dict_data[0]) * ret->capacity;
	ret->dict_data = (void **)malloc(data_sz);
	assert(ret->dict_data != NULL);

	memset(ret->dict_data, 0, data_sz);

	return ret;
}

bool
dict_contains(dict_t *dict, dict_key_t key)
{
	if (key >= dict->capacity) {
		return false;
	} else if (dict->dict_data[key] != NULL) {
		return true;
	} else {
		return false;
	}
}

void *
dict_get(dict_t *dict, dict_key_t key)
{
	if (key >= dict->capacity) {
		return NULL;
	} else if (dict->dict_data[key] != NULL) {
		return dict->dict_data[key];
	} else {
		return NULL;
	}
}

static void
expand(dict_t *dict)
{
	size_t new_capacity = 2 * dict->capacity;

	dict->dict_data = realloc(dict->dict_data,
				  new_capacity * sizeof(dict->dict_data[0]));
	assert(dict->dict_data != NULL);

	memset(dict->dict_data + dict->capacity, 0,
	       (new_capacity - dict->capacity) * sizeof(dict->dict_data[0]));
	dict->capacity = new_capacity;
}

static void
expand_for(dict_t *dict, size_t capacity)
{
	while (capacity > dict->capacity) {
		// internal decision: limit dict to certain level
		assert(dict->capacity < CAPACITY_LIMITATION);
		expand(dict);
	}
}

dict_key_t
dict_get_first_free_key_from(dict_t *dict, dict_key_t from)
{
	// FIXME: slow version, add more to improve performance
	dict_key_t key;

	for (key = from; key < dict->capacity; ++key) {
		if (dict->dict_data[key] == NULL) {
			return key;
		}
	}

	expand(dict);

	return key;
}

dict_key_t
dict_get_first_free_key(dict_t *dict)
{
	return dict_get_first_free_key_from(dict, 0U);
}

void
dict_add(dict_t *dict, dict_key_t key, void *element)
{
	if (key >= dict->capacity) {
		expand_for(dict, key + 1);
	}

	assert(key < dict->capacity);
	assert(dict->dict_data[key] == NULL);
	dict->dict_data[key] = element;

	return;
}

void
dict_remove(dict_t *dict, dict_key_t key)
{
	assert(key < dict->capacity);
	assert(dict->dict_data[key] != NULL);
	dict->dict_data[key] = NULL;
}

void
dict_deinit(dict_t *dict)
{
	free(dict);
}
