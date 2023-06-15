// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef uint32_t      dict_key_t;
typedef struct dict_s dict_t;

typedef struct {
	error_t	   err;
	dict_key_t key;
} dict_key_ret_t;

// Initialize a new dictionary
dict_t *
dict_init(dict_key_t key_min, dict_key_t key_max);

// Does the key exist in the dictionary
bool
dict_contains(dict_t *dict, dict_key_t key);

// Get the data for a specified key, or NULL
void *
dict_get(dict_t *dict, dict_key_t key);

// Find the first unused key in the dictionary
dict_key_ret_t
dict_get_first_free_key(dict_t *dict);

// Find the first unused key in the dictionary, starting from
dict_key_ret_t
dict_get_first_free_key_from(dict_t *dict, dict_key_t from);

// Add an entry to the dictionary, data may not be NULL
error_t
dict_add(dict_t *dict, dict_key_t key, void *data);

// Remove key from dict. Returns the stored value in *data if data is not NULL
// The caller is responsible to free the returned data.
error_t
dict_remove(dict_t *dict, dict_key_t key, void **data);

void
dict_deinit(dict_t *dict);

dict_key_t
dict_get_min_key(dict_t *dict);

dict_key_t
dict_get_max_key(dict_t *dict);

#define dict_foreach(info, key, dict)                                          \
	for (key = dict_get_min_key(dict), info		= dict_get(dict, key); \
	     key <= dict_get_max_key(dict); key++, info = dict_get(dict, key))
