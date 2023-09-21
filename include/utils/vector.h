// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// A simple dynamic array. Memory may or maynot be contiguous.
// It's not thread safe.

typedef struct vector_s vector_t;

// Initialize a vector, with min_capacity in units of items
// and capacity_step_sz in units of items. If capacity_step_sz
// or min_capacity are zero, defaults are used.
#define vector_init(type, min_capacity, capacity_step_sz)                      \
	vector_init_internal(min_capacity, capacity_step_sz, sizeof(type))

vector_t *
vector_init_internal(count_t init_capacity, count_t capacity_step_sz,
		     size_t element_sz);

void
vector_deinit(vector_t *vector);

#define vector_push_back_imm(type, vector, val, err)                           \
	do {                                                                   \
		type tmp = val;                                                \
		err	 = vector_push_back_internal(vector, &tmp);            \
	} while (0)

#define vector_push_back(vector, val) vector_push_back_internal(vector, &val)

error_t
vector_push_back_internal(vector_t *vector, const void *val);

#define vector_pop_back(type, vector) ((type *)vector_pop_back_internal(vector))

void *
vector_pop_back_internal(vector_t *vector);

// Swap to tail first, then delete the tail. Avoid normal deletion cost, but
// the order is not kept.
void
vector_delete(vector_t *vector, index_t idx);

void
vector_delete_keep_order(vector_t *vector, index_t idx);

void
vector_swap(vector_t *vector, index_t idx1, index_t idx2);

count_t
vector_size(const vector_t *vector);

#define vector_at(type, vector, idx) (*(type *)vector_at_internal(vector, idx))

#define vector_at_ptr(type, vector, idx)                                       \
	((type *)vector_at_internal(vector, idx))

void *
vector_at_internal(const vector_t *vector, index_t idx);

void *
vector_raw_data(const vector_t *vector);

index_t
vector_end(const vector_t *vector);

bool
vector_is_empty(const vector_t *vector);

typedef bool (*vector_find_check_t)(void *val, void *target);

bool
vector_find(const vector_t *vector, vector_find_check_t func, void *target,
	    index_t *idx);

#define foreach_vector_ptr(element_type, vector, idx, element_ptr)             \
	for ((idx)	  = 0,                                                 \
	    (element_ptr) = vector_at_ptr(element_type, (vector), (idx));      \
	     (idx) < vector_size((vector)); ++(idx),                           \
	    (element_ptr) = vector_at_ptr(element_type, (vector), (idx)))

#define foreach_vector(element_type, vector, idx, element)                     \
	for ((idx)    = 0,                                                     \
	    (element) = vector_size((vector)) == 0                             \
				? (element_type){ 0 }                          \
				: vector_at(element_type, (vector), (idx));    \
	     (idx) < vector_size((vector));                                    \
	     ++(idx),                                                          \
	    (element) = (idx) < vector_size((vector))                          \
				? vector_at(element_type, (vector), (idx))     \
				: (element_type){ 0 })
