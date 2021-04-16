// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef uint64_t dict_key_t;

typedef struct {
	size_t capacity;
	void **dict_data;
} dict_t;

// Initial with default capacity, increase when add more
dict_t *
dict_init(void);

bool
dict_contains(dict_t *dict, dict_key_t key);

void *
dict_get(dict_t *dict, dict_key_t key);

// must successfully return a key, or assert
dict_key_t
dict_get_first_free_key(dict_t *dict);

dict_key_t
dict_get_first_free_key_from(dict_t *dict, dict_key_t from);

// must success, or assert
void
dict_add(dict_t *dict, dict_key_t key, void *element);

// remove key from dict, and set the element to NULL
// it's caller's responsibility to free memory
void
dict_remove(dict_t *dict, dict_key_t key);

void
dict_deinit(dict_t *dict);
