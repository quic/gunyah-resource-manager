// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <utils/vector.h>

#define DEFAULT_INIT_CAPACITY (64)
#define DEFAULT_CAPACITY_STEP (64)

struct vector {
	void *data;
	// minimum capacity
	size_t min_capacity;
	// capacity measured by element
	size_t capacity;
	// size of vector in elements
	size_t elements;
	// vector grows or shrinks by step-size elements
	size_t capacity_step_sz;
	// size of an element
	size_t element_sz;
	// NOTE: have issue for multiple thread accessing
	void *internal_tmp;
};

static error_t
vector_resize(vector_t *vector);

// Placeholder
static void *
vector_pop_back_threadsafe_internal(vector_t *vector, void *tmp);

// Placeholder
static void
vector_swap_threadsafe(vector_t *vector, index_t idx1, index_t idx2, void *tmp);

vector_t *
vector_init_internal(size_t init_capacity, size_t capacity_step_sz,
		     size_t element_sz)
{
	vector_t *ret = calloc(1, sizeof(*ret));
	if (ret == NULL) {
		goto err;
	}

	ret->element_sz = element_sz;

	if (init_capacity == 0) {
		ret->capacity = DEFAULT_INIT_CAPACITY;
	} else {
		ret->capacity = init_capacity;
	}
	ret->min_capacity = ret->capacity;

	ret->data = calloc(ret->capacity, ret->element_sz);
	if (ret->data == NULL) {
		goto err1;
	}

	if (capacity_step_sz == 0) {
		ret->capacity_step_sz = DEFAULT_CAPACITY_STEP;
	} else {
		ret->capacity_step_sz = capacity_step_sz;
	}

	ret->elements = 0;

	ret->internal_tmp = malloc(ret->element_sz);
	if (ret->internal_tmp == NULL) {
		goto err2;
	}

	return ret;

err2:
	if (ret->data != NULL) {
		free(ret->data);
	}
err1:
	if (ret != NULL) {
		free(ret);
	}
err:
	return NULL;
}

void
vector_deinit(vector_t *vector)
{
	if (vector != NULL) {
		if (vector->internal_tmp != NULL) {
			free(vector->internal_tmp);
			vector->internal_tmp = NULL;
		}

		if (vector->data != NULL) {
			free(vector->data);
			vector->data = NULL;
		}

		free(vector);
	}
}

error_t
vector_push_back_internal(vector_t *vector, const void *element)
{
	error_t e = OK;

	if (vector->data == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}
	e = vector_resize(vector);
	if (e != OK) {
		goto err;
	}

	uintptr_t base	 = (uintptr_t)vector->data;
	size_t	  offset = vector->elements * vector->element_sz;
	memcpy((void *)(base + offset), element, vector->element_sz);
	vector->elements++;

err:
	return e;
}

void *
vector_pop_back_internal(vector_t *vector)
{
	return vector_pop_back_threadsafe_internal(vector,
						   vector->internal_tmp);
}

void *
vector_pop_back_threadsafe_internal(vector_t *vector, void *tmp)
{
	if (vector->elements == 0) {
		tmp = NULL;
		goto out;
	}
	if (vector->data == NULL) {
		tmp = NULL;
		goto out;
	}
	vector->elements--;

	uintptr_t base	 = (uintptr_t)vector->data;
	size_t	  offset = vector->elements * vector->element_sz;

	void *ret = (void *)(base + offset);
	memcpy(tmp, ret, vector->element_sz);

	(void)vector_resize(vector);

out:
	return tmp;
}

error_t
vector_insert_internal(vector_t *vector, index_t idx, const void *element)
{
	error_t e = OK;

	if (vector->data == NULL) {
		e = ERROR_NOMEM;
		goto err;
	}
	assert(vector->elements > idx);
	e = vector_resize(vector);
	if (e != OK) {
		goto err;
	}

	size_t sz = vector->elements - idx;
	sz *= vector->element_sz;

	uintptr_t base	     = (uintptr_t)vector->data;
	size_t	  offset_dst = (idx + 1) * vector->element_sz;
	size_t	  offset_src = idx * vector->element_sz;

	memcpy((void *)(base + offset_dst), (void *)(base + offset_src), sz);

	// set value to element at idx
	memcpy((void *)(base + offset_src), element, vector->element_sz);

	vector->elements++;
err:
	return e;
}

void
vector_delete_keep_order(vector_t *vector, index_t idx)
{
	assert(vector->elements > idx);

	if (vector->data == NULL) {
		goto out;
	}

	size_t sz = vector->elements - (idx + 1);
	sz *= vector->element_sz;

	uintptr_t base	     = (uintptr_t)vector->data;
	size_t	  offset_src = (idx + 1) * vector->element_sz;
	size_t	  offset_dst = idx * vector->element_sz;

	if (sz != 0) {
		memcpy((void *)(base + offset_dst), (void *)(base + offset_src),
		       sz);
	}
	vector->elements--;

	(void)vector_resize(vector);
out:
	return;
}

void
vector_delete(vector_t *vector, index_t idx)
{
	vector_swap(vector, idx, vector_end(vector));
	vector_delete_keep_order(vector, vector_end(vector));
}

void
vector_swap(vector_t *vector, index_t idx1, index_t idx2)
{
	vector_swap_threadsafe(vector, idx1, idx2, vector->internal_tmp);
}

void
vector_swap_threadsafe(vector_t *vector, index_t idx1, index_t idx2, void *tmp)
{
	if (vector->data == NULL) {
		goto out;
	}

	if (idx1 == idx2) {
		goto out;
	}

	uintptr_t base	  = (uintptr_t)vector->data;
	size_t	  offset1 = idx1 * vector->element_sz;
	size_t	  offset2 = idx2 * vector->element_sz;

	// 1 -> tmp
	memcpy(tmp, (void *)(base + offset1), vector->element_sz);
	// 2 -> 1
	memcpy((void *)(base + offset1), (void *)(base + offset2),
	       vector->element_sz);
	// tmp -> 2
	memcpy((void *)(base + offset2), tmp, vector->element_sz);

out:
	return;
}

size_t
vector_size(const vector_t *vector)
{
	return vector->elements;
}

error_t
vector_resize(vector_t *vector)
{
	error_t e = OK;

	if (vector->data == NULL) {
		e = ERROR_NOMEM;
		goto out;
	}

	size_t capacity = vector->capacity;

	if ((capacity - vector->elements) >= vector->capacity_step_sz) {
		if (capacity > vector->min_capacity) {
			capacity -= vector->capacity_step_sz;
		}
	} else if (capacity == vector->elements) {
		capacity += vector->capacity_step_sz;
	} else {
		goto out;
	}

	if ((capacity > 0) && (capacity != vector->capacity)) {
		size_t sz    = capacity * vector->element_sz;
		vector->data = realloc(vector->data, sz);
		if (vector->data == NULL) {
			e = ERROR_NOMEM;
			goto out;
		}

		vector->capacity = capacity;
	}
out:
	return e;
}

void *
vector_at_internal(const vector_t *vector, index_t idx)
{
	void *ret = NULL;

	assert((vector != NULL) && (vector->data != NULL));

	if (idx >= vector->elements) {
		goto out;
	}

	uintptr_t base	 = (uintptr_t)vector->data;
	size_t	  offset = idx * vector->element_sz;

	ret = (void *)(base + offset);

out:
	return ret;
}

index_t
vector_end(const vector_t *vector)
{
	return vector->elements != 0 ? (index_t)(vector->elements - 1) : 0U;
}

bool
vector_is_empty(const vector_t *vector)
{
	return vector->elements == 0;
}

bool
vector_find(const vector_t *vector, vector_find_check_t func, void *target,
	    index_t *idx)
{
	bool found = false;
	for (index_t i = 0; i < vector_size(vector); ++i) {
		if (func(vector_at_internal(vector, i), target)) {
			*idx  = i;
			found = true;
			break;
		}
	}

	return found;
}

void *
vector_raw_data(const vector_t *vector)
{
	return vector->data;
}
