// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

typedef struct boot_env_phys_range boot_env_phys_range_t;
typedef struct boot_env_data	   boot_env_data_t;

typedef uint32_t count_t;
typedef uint32_t index_t;
#define BOOT_ENV_RANGES_NUM 32
typedef uint16_t cpu_index_t;
typedef uint64_t cap_id_t;
#define CSPACE_CAP_INVALID (cap_id_t)18446744073709551615U // 0xffffffffffffffff
typedef uint64_t paddr_t;
#define MSGQUEUE_DELAY_UNCHANGED     (count_t)4294967295U // 0xffffffff
#define MSGQUEUE_MAX_MAX_MSG_SIZE    (count_t)1024U	  // 0x400
#define MSGQUEUE_MAX_QUEUE_DEPTH     (count_t)256U	  // 0x100
#define MSGQUEUE_THRESHOLD_MAXIMUM   (count_t)4294967294U // 0xfffffffe
#define MSGQUEUE_THRESHOLD_UNCHANGED (count_t)4294967295U // 0xffffffff
typedef uint32_t priority_t;
#define SCHEDULER_DEFAULT_PRIORITY (priority_t)32U // 0x20
typedef uint64_t nanoseconds_t;
#define SCHEDULER_DEFAULT_TIMESLICE (nanoseconds_t)5000000U   // 0x4c4b40
#define SCHEDULER_MAX_PRIORITY	    (priority_t)63U	      // 0x3f
#define SCHEDULER_MAX_TIMESLICE	    (nanoseconds_t)100000000U // 0x5f5e100
#define SCHEDULER_MIN_PRIORITY	    (priority_t)0U	      // 0x0
#define SCHEDULER_MIN_TIMESLICE	    (nanoseconds_t)100000U    // 0x186a0
typedef enum scheduler_variant {
	SCHEDULER_VARIANT_TRIVIAL = 0,
	SCHEDULER_VARIANT_FPRR	  = 1
} scheduler_variant_t;

#define SCHEDULER_VARIANT__MAX (scheduler_variant_t)(1U)
#define SCHEDULER_VARIANT__MIN (scheduler_variant_t)(0U)

typedef uint16_t vmid_t;
typedef uint64_t register_t;
struct boot_env_phys_range {
	paddr_t base;
	size_t	size;
};

typedef uint64_t vmaddr_t;
struct boot_env_data {
	boot_env_phys_range_t free_ranges[32];
	count_t		      free_ranges_count;
	uint8_t		      pad_to_timer_freq_[4];
	uint64_t	      timer_freq;
	cap_id_t	      addrspace_capid;
	cap_id_t	      device_me_capid;
	vmaddr_t	      device_me_base;
	vmaddr_t	      entry_hlos;
	vmaddr_t	      hlos_vm_base;
	size_t		      hlos_vm_size;
	vmaddr_t	      hlos_dt_base;
	vmaddr_t	      hlos_ramfs_base;
	bool		      watchdog_supported;
	uint8_t		      pad_to_uart_me_capid_[7];
	cap_id_t	      uart_me_capid;
	paddr_t		      uart_address;
	cap_id_t	      partition_capid;
	cap_id_t	      cspace_capid;
	cap_id_t	      vcpu_capid;
	vmaddr_t	      entry_ipa;
	vmaddr_t	      env_ipa;
	cap_id_t	      me_capid;
	vmaddr_t	      me_ipa_base;
	size_t		      me_size;
	uintptr_t	      ipa_offset;
	vmaddr_t	      app_ipa;
	vmaddr_t	      runtime_ipa;
	uint64_t	      usable_cores;
	cpu_index_t	      boot_core;
	uint8_t		      pad_to_app_heap_ipa_[6];
	vmaddr_t	      app_heap_ipa;
	size_t		      app_heap_size;
	cap_id_t	      vic;
	cap_id_t	      vic_hwirq[1020];
	cap_id_t	      vic_msi_source[16];
	paddr_t		      gicd_base;
	paddr_t		      gicr_base;
	size_t		      gicr_stride;
	paddr_t		      gits_base;
	size_t		      gits_stride;
};

typedef uint32_t cap_rights_t;

// Bitfield: cap_rights_addrspace <uint32_t>
typedef struct cap_rights_addrspace {
	// 0         bool attach
	// 1         bool map
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_addrspace_t;

#define cap_rights_addrspace_default()                                         \
	(cap_rights_addrspace_t)                                               \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_addrspace_cast(val_0)                                       \
	(cap_rights_addrspace_t)                                               \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_addrspace_raw(cap_rights_addrspace_t bit_field);

_Atomic uint32_t *
cap_rights_addrspace_atomic_ptr_raw(_Atomic cap_rights_addrspace_t *ptr);

void
cap_rights_addrspace_init(cap_rights_addrspace_t *bit_field);

cap_rights_addrspace_t
cap_rights_addrspace_clean(cap_rights_addrspace_t val);

bool
cap_rights_addrspace_is_equal(cap_rights_addrspace_t b1,
			      cap_rights_addrspace_t b2);

// Union of boolean fields of two cap_rights_addrspace_t values
cap_rights_addrspace_t
cap_rights_addrspace_union(cap_rights_addrspace_t b1,
			   cap_rights_addrspace_t b2);

// Intersection of boolean fields of two cap_rights_addrspace_t values
cap_rights_addrspace_t
cap_rights_addrspace_intersection(cap_rights_addrspace_t b1,
				  cap_rights_addrspace_t b2);

// Invert all boolean fields in a cap_rights_addrspace_t value
cap_rights_addrspace_t
cap_rights_addrspace_inverse(cap_rights_addrspace_t b);

// Set difference of boolean fields of two cap_rights_addrspace_t values
cap_rights_addrspace_t
cap_rights_addrspace_difference(cap_rights_addrspace_t b1,
				cap_rights_addrspace_t b2);

// Atomically replace a cap_rights_addrspace_t value with the union of its
// boolean fields with a given cap_rights_addrspace_t value, and return the
// previous value.
cap_rights_addrspace_t
cap_rights_addrspace_atomic_union(_Atomic cap_rights_addrspace_t *b1,
				  cap_rights_addrspace_t	  b2,
				  memory_order			  order);

// Atomically replace a cap_rights_addrspace_t value with the intersection of
// its boolean fields with a given cap_rights_addrspace_t value, and return the
// previous value.
cap_rights_addrspace_t
cap_rights_addrspace_atomic_intersection(_Atomic cap_rights_addrspace_t *b1,
					 cap_rights_addrspace_t		 b2,
					 memory_order			 order);

// Atomically replace a cap_rights_addrspace_t value with the set difference of
// its boolean fields and a given cap_rights_addrspace_t value, and return the
// previous value.
cap_rights_addrspace_t
cap_rights_addrspace_atomic_difference(_Atomic cap_rights_addrspace_t *b1,
				       cap_rights_addrspace_t	       b2,
				       memory_order		       order);

// Bitfield: cap_rights_cspace <uint32_t>
typedef struct cap_rights_cspace {
	// 0         bool cap_create
	// 1         bool cap_delete
	// 2         bool cap_copy
	// 3         bool attach
	// 4         bool cap_revoke
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_cspace_t;

#define cap_rights_cspace_default()                                            \
	(cap_rights_cspace_t)                                                  \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_cspace_cast(val_0)                                          \
	(cap_rights_cspace_t)                                                  \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_cspace_raw(cap_rights_cspace_t bit_field);

_Atomic uint32_t *
cap_rights_cspace_atomic_ptr_raw(_Atomic cap_rights_cspace_t *ptr);

void
cap_rights_cspace_init(cap_rights_cspace_t *bit_field);

cap_rights_cspace_t
cap_rights_cspace_clean(cap_rights_cspace_t val);

bool
cap_rights_cspace_is_equal(cap_rights_cspace_t b1, cap_rights_cspace_t b2);

// Union of boolean fields of two cap_rights_cspace_t values
cap_rights_cspace_t
cap_rights_cspace_union(cap_rights_cspace_t b1, cap_rights_cspace_t b2);

// Intersection of boolean fields of two cap_rights_cspace_t values
cap_rights_cspace_t
cap_rights_cspace_intersection(cap_rights_cspace_t b1, cap_rights_cspace_t b2);

// Invert all boolean fields in a cap_rights_cspace_t value
cap_rights_cspace_t
cap_rights_cspace_inverse(cap_rights_cspace_t b);

// Set difference of boolean fields of two cap_rights_cspace_t values
cap_rights_cspace_t
cap_rights_cspace_difference(cap_rights_cspace_t b1, cap_rights_cspace_t b2);

// Atomically replace a cap_rights_cspace_t value with the union of its boolean
// fields with a given cap_rights_cspace_t value, and return the previous value.
cap_rights_cspace_t
cap_rights_cspace_atomic_union(_Atomic cap_rights_cspace_t *b1,
			       cap_rights_cspace_t b2, memory_order order);

// Atomically replace a cap_rights_cspace_t value with the intersection of its
// boolean fields with a given cap_rights_cspace_t value, and return the
// previous value.
cap_rights_cspace_t
cap_rights_cspace_atomic_intersection(_Atomic cap_rights_cspace_t *b1,
				      cap_rights_cspace_t	   b2,
				      memory_order		   order);

// Atomically replace a cap_rights_cspace_t value with the set difference of its
// boolean fields and a given cap_rights_cspace_t value, and return the previous
// value.
cap_rights_cspace_t
cap_rights_cspace_atomic_difference(_Atomic cap_rights_cspace_t *b1,
				    cap_rights_cspace_t b2, memory_order order);

// Bitfield: cap_rights_doorbell <uint32_t>
typedef struct cap_rights_doorbell {
	// 0         bool send
	// 1         bool receive
	// 2         bool bind
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_doorbell_t;

#define cap_rights_doorbell_default()                                          \
	(cap_rights_doorbell_t)                                                \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_doorbell_cast(val_0)                                        \
	(cap_rights_doorbell_t)                                                \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_doorbell_raw(cap_rights_doorbell_t bit_field);

_Atomic uint32_t *
cap_rights_doorbell_atomic_ptr_raw(_Atomic cap_rights_doorbell_t *ptr);

void
cap_rights_doorbell_init(cap_rights_doorbell_t *bit_field);

cap_rights_doorbell_t
cap_rights_doorbell_clean(cap_rights_doorbell_t val);

bool
cap_rights_doorbell_is_equal(cap_rights_doorbell_t b1,
			     cap_rights_doorbell_t b2);

// Union of boolean fields of two cap_rights_doorbell_t values
cap_rights_doorbell_t
cap_rights_doorbell_union(cap_rights_doorbell_t b1, cap_rights_doorbell_t b2);

// Intersection of boolean fields of two cap_rights_doorbell_t values
cap_rights_doorbell_t
cap_rights_doorbell_intersection(cap_rights_doorbell_t b1,
				 cap_rights_doorbell_t b2);

// Invert all boolean fields in a cap_rights_doorbell_t value
cap_rights_doorbell_t
cap_rights_doorbell_inverse(cap_rights_doorbell_t b);

// Set difference of boolean fields of two cap_rights_doorbell_t values
cap_rights_doorbell_t
cap_rights_doorbell_difference(cap_rights_doorbell_t b1,
			       cap_rights_doorbell_t b2);

// Atomically replace a cap_rights_doorbell_t value with the union of its
// boolean fields with a given cap_rights_doorbell_t value, and return the
// previous value.
cap_rights_doorbell_t
cap_rights_doorbell_atomic_union(_Atomic cap_rights_doorbell_t *b1,
				 cap_rights_doorbell_t b2, memory_order order);

// Atomically replace a cap_rights_doorbell_t value with the intersection of its
// boolean fields with a given cap_rights_doorbell_t value, and return the
// previous value.
cap_rights_doorbell_t
cap_rights_doorbell_atomic_intersection(_Atomic cap_rights_doorbell_t *b1,
					cap_rights_doorbell_t	       b2,
					memory_order		       order);

// Atomically replace a cap_rights_doorbell_t value with the set difference of
// its boolean fields and a given cap_rights_doorbell_t value, and return the
// previous value.
cap_rights_doorbell_t
cap_rights_doorbell_atomic_difference(_Atomic cap_rights_doorbell_t *b1,
				      cap_rights_doorbell_t	     b2,
				      memory_order		     order);

// Bitfield: cap_rights_generic <uint32_t>
typedef struct cap_rights_generic {
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_generic_t;

#define cap_rights_generic_default()                                           \
	(cap_rights_generic_t)                                                 \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_generic_cast(val_0)                                         \
	(cap_rights_generic_t)                                                 \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_generic_raw(cap_rights_generic_t bit_field);

_Atomic uint32_t *
cap_rights_generic_atomic_ptr_raw(_Atomic cap_rights_generic_t *ptr);

void
cap_rights_generic_init(cap_rights_generic_t *bit_field);

cap_rights_generic_t
cap_rights_generic_clean(cap_rights_generic_t val);

bool
cap_rights_generic_is_equal(cap_rights_generic_t b1, cap_rights_generic_t b2);

// Union of boolean fields of two cap_rights_generic_t values
cap_rights_generic_t
cap_rights_generic_union(cap_rights_generic_t b1, cap_rights_generic_t b2);

// Intersection of boolean fields of two cap_rights_generic_t values
cap_rights_generic_t
cap_rights_generic_intersection(cap_rights_generic_t b1,
				cap_rights_generic_t b2);

// Invert all boolean fields in a cap_rights_generic_t value
cap_rights_generic_t
cap_rights_generic_inverse(cap_rights_generic_t b);

// Set difference of boolean fields of two cap_rights_generic_t values
cap_rights_generic_t
cap_rights_generic_difference(cap_rights_generic_t b1, cap_rights_generic_t b2);

// Atomically replace a cap_rights_generic_t value with the union of its boolean
// fields with a given cap_rights_generic_t value, and return the previous
// value.
cap_rights_generic_t
cap_rights_generic_atomic_union(_Atomic cap_rights_generic_t *b1,
				cap_rights_generic_t b2, memory_order order);

// Atomically replace a cap_rights_generic_t value with the intersection of its
// boolean fields with a given cap_rights_generic_t value, and return the
// previous value.
cap_rights_generic_t
cap_rights_generic_atomic_intersection(_Atomic cap_rights_generic_t *b1,
				       cap_rights_generic_t	     b2,
				       memory_order		     order);

// Atomically replace a cap_rights_generic_t value with the set difference of
// its boolean fields and a given cap_rights_generic_t value, and return the
// previous value.
cap_rights_generic_t
cap_rights_generic_atomic_difference(_Atomic cap_rights_generic_t *b1,
				     cap_rights_generic_t	   b2,
				     memory_order		   order);

// Bitfield: cap_rights_hwirq <uint32_t>
typedef struct cap_rights_hwirq {
	// 1         bool bind_vic
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_hwirq_t;

#define cap_rights_hwirq_default()                                             \
	(cap_rights_hwirq_t)                                                   \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_hwirq_cast(val_0)                                           \
	(cap_rights_hwirq_t)                                                   \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_hwirq_raw(cap_rights_hwirq_t bit_field);

_Atomic uint32_t *
cap_rights_hwirq_atomic_ptr_raw(_Atomic cap_rights_hwirq_t *ptr);

void
cap_rights_hwirq_init(cap_rights_hwirq_t *bit_field);

cap_rights_hwirq_t
cap_rights_hwirq_clean(cap_rights_hwirq_t val);

bool
cap_rights_hwirq_is_equal(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2);

// Union of boolean fields of two cap_rights_hwirq_t values
cap_rights_hwirq_t
cap_rights_hwirq_union(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2);

// Intersection of boolean fields of two cap_rights_hwirq_t values
cap_rights_hwirq_t
cap_rights_hwirq_intersection(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2);

// Invert all boolean fields in a cap_rights_hwirq_t value
cap_rights_hwirq_t
cap_rights_hwirq_inverse(cap_rights_hwirq_t b);

// Set difference of boolean fields of two cap_rights_hwirq_t values
cap_rights_hwirq_t
cap_rights_hwirq_difference(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2);

// Atomically replace a cap_rights_hwirq_t value with the union of its boolean
// fields with a given cap_rights_hwirq_t value, and return the previous value.
cap_rights_hwirq_t
cap_rights_hwirq_atomic_union(_Atomic cap_rights_hwirq_t *b1,
			      cap_rights_hwirq_t b2, memory_order order);

// Atomically replace a cap_rights_hwirq_t value with the intersection of its
// boolean fields with a given cap_rights_hwirq_t value, and return the previous
// value.
cap_rights_hwirq_t
cap_rights_hwirq_atomic_intersection(_Atomic cap_rights_hwirq_t *b1,
				     cap_rights_hwirq_t b2, memory_order order);

// Atomically replace a cap_rights_hwirq_t value with the set difference of its
// boolean fields and a given cap_rights_hwirq_t value, and return the previous
// value.
cap_rights_hwirq_t
cap_rights_hwirq_atomic_difference(_Atomic cap_rights_hwirq_t *b1,
				   cap_rights_hwirq_t b2, memory_order order);

// Bitfield: cap_rights_memextent <uint32_t>
typedef struct cap_rights_memextent {
	// 0         bool map
	// 1         bool derive
	// 2         bool attach
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_memextent_t;

#define cap_rights_memextent_default()                                         \
	(cap_rights_memextent_t)                                               \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_memextent_cast(val_0)                                       \
	(cap_rights_memextent_t)                                               \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_memextent_raw(cap_rights_memextent_t bit_field);

_Atomic uint32_t *
cap_rights_memextent_atomic_ptr_raw(_Atomic cap_rights_memextent_t *ptr);

void
cap_rights_memextent_init(cap_rights_memextent_t *bit_field);

cap_rights_memextent_t
cap_rights_memextent_clean(cap_rights_memextent_t val);

bool
cap_rights_memextent_is_equal(cap_rights_memextent_t b1,
			      cap_rights_memextent_t b2);

// Union of boolean fields of two cap_rights_memextent_t values
cap_rights_memextent_t
cap_rights_memextent_union(cap_rights_memextent_t b1,
			   cap_rights_memextent_t b2);

// Intersection of boolean fields of two cap_rights_memextent_t values
cap_rights_memextent_t
cap_rights_memextent_intersection(cap_rights_memextent_t b1,
				  cap_rights_memextent_t b2);

// Invert all boolean fields in a cap_rights_memextent_t value
cap_rights_memextent_t
cap_rights_memextent_inverse(cap_rights_memextent_t b);

// Set difference of boolean fields of two cap_rights_memextent_t values
cap_rights_memextent_t
cap_rights_memextent_difference(cap_rights_memextent_t b1,
				cap_rights_memextent_t b2);

// Atomically replace a cap_rights_memextent_t value with the union of its
// boolean fields with a given cap_rights_memextent_t value, and return the
// previous value.
cap_rights_memextent_t
cap_rights_memextent_atomic_union(_Atomic cap_rights_memextent_t *b1,
				  cap_rights_memextent_t	  b2,
				  memory_order			  order);

// Atomically replace a cap_rights_memextent_t value with the intersection of
// its boolean fields with a given cap_rights_memextent_t value, and return the
// previous value.
cap_rights_memextent_t
cap_rights_memextent_atomic_intersection(_Atomic cap_rights_memextent_t *b1,
					 cap_rights_memextent_t		 b2,
					 memory_order			 order);

// Atomically replace a cap_rights_memextent_t value with the set difference of
// its boolean fields and a given cap_rights_memextent_t value, and return the
// previous value.
cap_rights_memextent_t
cap_rights_memextent_atomic_difference(_Atomic cap_rights_memextent_t *b1,
				       cap_rights_memextent_t	       b2,
				       memory_order		       order);

// Bitfield: cap_rights_msgqueue <uint32_t>
typedef struct cap_rights_msgqueue {
	// 0         bool send
	// 1         bool receive
	// 2         bool bind_send
	// 3         bool bind_receive
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_msgqueue_t;

#define cap_rights_msgqueue_default()                                          \
	(cap_rights_msgqueue_t)                                                \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_msgqueue_cast(val_0)                                        \
	(cap_rights_msgqueue_t)                                                \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_msgqueue_raw(cap_rights_msgqueue_t bit_field);

_Atomic uint32_t *
cap_rights_msgqueue_atomic_ptr_raw(_Atomic cap_rights_msgqueue_t *ptr);

void
cap_rights_msgqueue_init(cap_rights_msgqueue_t *bit_field);

cap_rights_msgqueue_t
cap_rights_msgqueue_clean(cap_rights_msgqueue_t val);

bool
cap_rights_msgqueue_is_equal(cap_rights_msgqueue_t b1,
			     cap_rights_msgqueue_t b2);

// Union of boolean fields of two cap_rights_msgqueue_t values
cap_rights_msgqueue_t
cap_rights_msgqueue_union(cap_rights_msgqueue_t b1, cap_rights_msgqueue_t b2);

// Intersection of boolean fields of two cap_rights_msgqueue_t values
cap_rights_msgqueue_t
cap_rights_msgqueue_intersection(cap_rights_msgqueue_t b1,
				 cap_rights_msgqueue_t b2);

// Invert all boolean fields in a cap_rights_msgqueue_t value
cap_rights_msgqueue_t
cap_rights_msgqueue_inverse(cap_rights_msgqueue_t b);

// Set difference of boolean fields of two cap_rights_msgqueue_t values
cap_rights_msgqueue_t
cap_rights_msgqueue_difference(cap_rights_msgqueue_t b1,
			       cap_rights_msgqueue_t b2);

// Atomically replace a cap_rights_msgqueue_t value with the union of its
// boolean fields with a given cap_rights_msgqueue_t value, and return the
// previous value.
cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_union(_Atomic cap_rights_msgqueue_t *b1,
				 cap_rights_msgqueue_t b2, memory_order order);

// Atomically replace a cap_rights_msgqueue_t value with the intersection of its
// boolean fields with a given cap_rights_msgqueue_t value, and return the
// previous value.
cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_intersection(_Atomic cap_rights_msgqueue_t *b1,
					cap_rights_msgqueue_t	       b2,
					memory_order		       order);

// Atomically replace a cap_rights_msgqueue_t value with the set difference of
// its boolean fields and a given cap_rights_msgqueue_t value, and return the
// previous value.
cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_difference(_Atomic cap_rights_msgqueue_t *b1,
				      cap_rights_msgqueue_t	     b2,
				      memory_order		     order);

// Bitfield: cap_rights_partition <uint32_t>
typedef struct cap_rights_partition {
	// 0         bool object_create
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_partition_t;

#define cap_rights_partition_default()                                         \
	(cap_rights_partition_t)                                               \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_partition_cast(val_0)                                       \
	(cap_rights_partition_t)                                               \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_partition_raw(cap_rights_partition_t bit_field);

_Atomic uint32_t *
cap_rights_partition_atomic_ptr_raw(_Atomic cap_rights_partition_t *ptr);

void
cap_rights_partition_init(cap_rights_partition_t *bit_field);

cap_rights_partition_t
cap_rights_partition_clean(cap_rights_partition_t val);

bool
cap_rights_partition_is_equal(cap_rights_partition_t b1,
			      cap_rights_partition_t b2);

// Union of boolean fields of two cap_rights_partition_t values
cap_rights_partition_t
cap_rights_partition_union(cap_rights_partition_t b1,
			   cap_rights_partition_t b2);

// Intersection of boolean fields of two cap_rights_partition_t values
cap_rights_partition_t
cap_rights_partition_intersection(cap_rights_partition_t b1,
				  cap_rights_partition_t b2);

// Invert all boolean fields in a cap_rights_partition_t value
cap_rights_partition_t
cap_rights_partition_inverse(cap_rights_partition_t b);

// Set difference of boolean fields of two cap_rights_partition_t values
cap_rights_partition_t
cap_rights_partition_difference(cap_rights_partition_t b1,
				cap_rights_partition_t b2);

// Atomically replace a cap_rights_partition_t value with the union of its
// boolean fields with a given cap_rights_partition_t value, and return the
// previous value.
cap_rights_partition_t
cap_rights_partition_atomic_union(_Atomic cap_rights_partition_t *b1,
				  cap_rights_partition_t	  b2,
				  memory_order			  order);

// Atomically replace a cap_rights_partition_t value with the intersection of
// its boolean fields with a given cap_rights_partition_t value, and return the
// previous value.
cap_rights_partition_t
cap_rights_partition_atomic_intersection(_Atomic cap_rights_partition_t *b1,
					 cap_rights_partition_t		 b2,
					 memory_order			 order);

// Atomically replace a cap_rights_partition_t value with the set difference of
// its boolean fields and a given cap_rights_partition_t value, and return the
// previous value.
cap_rights_partition_t
cap_rights_partition_atomic_difference(_Atomic cap_rights_partition_t *b1,
				       cap_rights_partition_t	       b2,
				       memory_order		       order);

// Bitfield: cap_rights_thread <uint32_t>
typedef struct cap_rights_thread {
	// 0         bool power
	// 1         bool affinity
	// 2         bool priority
	// 3         bool timeslice
	// 4         bool yield_to
	// 7         bool lifecycle
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_thread_t;

#define cap_rights_thread_default()                                            \
	(cap_rights_thread_t)                                                  \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_thread_cast(val_0)                                          \
	(cap_rights_thread_t)                                                  \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_thread_raw(cap_rights_thread_t bit_field);

_Atomic uint32_t *
cap_rights_thread_atomic_ptr_raw(_Atomic cap_rights_thread_t *ptr);

void
cap_rights_thread_init(cap_rights_thread_t *bit_field);

cap_rights_thread_t
cap_rights_thread_clean(cap_rights_thread_t val);

bool
cap_rights_thread_is_equal(cap_rights_thread_t b1, cap_rights_thread_t b2);

// Union of boolean fields of two cap_rights_thread_t values
cap_rights_thread_t
cap_rights_thread_union(cap_rights_thread_t b1, cap_rights_thread_t b2);

// Intersection of boolean fields of two cap_rights_thread_t values
cap_rights_thread_t
cap_rights_thread_intersection(cap_rights_thread_t b1, cap_rights_thread_t b2);

// Invert all boolean fields in a cap_rights_thread_t value
cap_rights_thread_t
cap_rights_thread_inverse(cap_rights_thread_t b);

// Set difference of boolean fields of two cap_rights_thread_t values
cap_rights_thread_t
cap_rights_thread_difference(cap_rights_thread_t b1, cap_rights_thread_t b2);

// Atomically replace a cap_rights_thread_t value with the union of its boolean
// fields with a given cap_rights_thread_t value, and return the previous value.
cap_rights_thread_t
cap_rights_thread_atomic_union(_Atomic cap_rights_thread_t *b1,
			       cap_rights_thread_t b2, memory_order order);

// Atomically replace a cap_rights_thread_t value with the intersection of its
// boolean fields with a given cap_rights_thread_t value, and return the
// previous value.
cap_rights_thread_t
cap_rights_thread_atomic_intersection(_Atomic cap_rights_thread_t *b1,
				      cap_rights_thread_t	   b2,
				      memory_order		   order);

// Atomically replace a cap_rights_thread_t value with the set difference of its
// boolean fields and a given cap_rights_thread_t value, and return the previous
// value.
cap_rights_thread_t
cap_rights_thread_atomic_difference(_Atomic cap_rights_thread_t *b1,
				    cap_rights_thread_t b2, memory_order order);

// Bitfield: cap_rights_vic <uint32_t>
typedef struct cap_rights_vic {
	// 0         bool bind_source
	// 1         bool attach_vcpu
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vic_t;

#define cap_rights_vic_default()                                               \
	(cap_rights_vic_t)                                                     \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_vic_cast(val_0)                                             \
	(cap_rights_vic_t)                                                     \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_vic_raw(cap_rights_vic_t bit_field);

_Atomic uint32_t *
cap_rights_vic_atomic_ptr_raw(_Atomic cap_rights_vic_t *ptr);

void
cap_rights_vic_init(cap_rights_vic_t *bit_field);

cap_rights_vic_t
cap_rights_vic_clean(cap_rights_vic_t val);

bool
cap_rights_vic_is_equal(cap_rights_vic_t b1, cap_rights_vic_t b2);

// Union of boolean fields of two cap_rights_vic_t values
cap_rights_vic_t
cap_rights_vic_union(cap_rights_vic_t b1, cap_rights_vic_t b2);

// Intersection of boolean fields of two cap_rights_vic_t values
cap_rights_vic_t
cap_rights_vic_intersection(cap_rights_vic_t b1, cap_rights_vic_t b2);

// Invert all boolean fields in a cap_rights_vic_t value
cap_rights_vic_t
cap_rights_vic_inverse(cap_rights_vic_t b);

// Set difference of boolean fields of two cap_rights_vic_t values
cap_rights_vic_t
cap_rights_vic_difference(cap_rights_vic_t b1, cap_rights_vic_t b2);

// Atomically replace a cap_rights_vic_t value with the union of its boolean
// fields with a given cap_rights_vic_t value, and return the previous value.
cap_rights_vic_t
cap_rights_vic_atomic_union(_Atomic cap_rights_vic_t *b1, cap_rights_vic_t b2,
			    memory_order order);

// Atomically replace a cap_rights_vic_t value with the intersection of its
// boolean fields with a given cap_rights_vic_t value, and return the previous
// value.
cap_rights_vic_t
cap_rights_vic_atomic_intersection(_Atomic cap_rights_vic_t *b1,
				   cap_rights_vic_t b2, memory_order order);

// Atomically replace a cap_rights_vic_t value with the set difference of its
// boolean fields and a given cap_rights_vic_t value, and return the previous
// value.
cap_rights_vic_t
cap_rights_vic_atomic_difference(_Atomic cap_rights_vic_t *b1,
				 cap_rights_vic_t b2, memory_order order);

// Bitfield: cap_rights_vpm_group <uint32_t>
typedef struct cap_rights_vpm_group {
	// 0         bool attach_vcpu
	// 1         bool bind_virq
	// 2         bool query
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vpm_group_t;

#define cap_rights_vpm_group_default()                                         \
	(cap_rights_vpm_group_t)                                               \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define cap_rights_vpm_group_cast(val_0)                                       \
	(cap_rights_vpm_group_t)                                               \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
cap_rights_vpm_group_raw(cap_rights_vpm_group_t bit_field);

_Atomic uint32_t *
cap_rights_vpm_group_atomic_ptr_raw(_Atomic cap_rights_vpm_group_t *ptr);

void
cap_rights_vpm_group_init(cap_rights_vpm_group_t *bit_field);

cap_rights_vpm_group_t
cap_rights_vpm_group_clean(cap_rights_vpm_group_t val);

bool
cap_rights_vpm_group_is_equal(cap_rights_vpm_group_t b1,
			      cap_rights_vpm_group_t b2);

// Union of boolean fields of two cap_rights_vpm_group_t values
cap_rights_vpm_group_t
cap_rights_vpm_group_union(cap_rights_vpm_group_t b1,
			   cap_rights_vpm_group_t b2);

// Intersection of boolean fields of two cap_rights_vpm_group_t values
cap_rights_vpm_group_t
cap_rights_vpm_group_intersection(cap_rights_vpm_group_t b1,
				  cap_rights_vpm_group_t b2);

// Invert all boolean fields in a cap_rights_vpm_group_t value
cap_rights_vpm_group_t
cap_rights_vpm_group_inverse(cap_rights_vpm_group_t b);

// Set difference of boolean fields of two cap_rights_vpm_group_t values
cap_rights_vpm_group_t
cap_rights_vpm_group_difference(cap_rights_vpm_group_t b1,
				cap_rights_vpm_group_t b2);

// Atomically replace a cap_rights_vpm_group_t value with the union of its
// boolean fields with a given cap_rights_vpm_group_t value, and return the
// previous value.
cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_union(_Atomic cap_rights_vpm_group_t *b1,
				  cap_rights_vpm_group_t	  b2,
				  memory_order			  order);

// Atomically replace a cap_rights_vpm_group_t value with the intersection of
// its boolean fields with a given cap_rights_vpm_group_t value, and return the
// previous value.
cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_intersection(_Atomic cap_rights_vpm_group_t *b1,
					 cap_rights_vpm_group_t		 b2,
					 memory_order			 order);

// Atomically replace a cap_rights_vpm_group_t value with the set difference of
// its boolean fields and a given cap_rights_vpm_group_t value, and return the
// previous value.
cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_difference(_Atomic cap_rights_vpm_group_t *b1,
				       cap_rights_vpm_group_t	       b2,
				       memory_order		       order);
typedef uint32_t virq_t;
typedef enum error {
	ERROR_RETRY			  = -2,
	ERROR_UNIMPLEMENTED		  = -1,
	OK				  = 0,
	ERROR_ARGUMENT_INVALID		  = 1,
	ERROR_ARGUMENT_SIZE		  = 2,
	ERROR_ARGUMENT_ALIGNMENT	  = 3,
	ERROR_NOMEM			  = 10,
	ERROR_NORESOURCES		  = 11,
	ERROR_ADDR_OVERFLOW		  = 20,
	ERROR_ADDR_UNDERFLOW		  = 21,
	ERROR_ADDR_INVALID		  = 22,
	ERROR_DENIED			  = 30,
	ERROR_BUSY			  = 31,
	ERROR_IDLE			  = 32,
	ERROR_OBJECT_STATE		  = 33,
	ERROR_OBJECT_CONFIG		  = 34,
	ERROR_OBJECT_CONFIGURED		  = 35,
	ERROR_FAILURE			  = 36,
	ERROR_VIRQ_BOUND		  = 40,
	ERROR_VIRQ_NOT_BOUND		  = 41,
	ERROR_CSPACE_CAP_NULL		  = 50,
	ERROR_CSPACE_CAP_REVOKED	  = 51,
	ERROR_CSPACE_WRONG_OBJECT_TYPE	  = 52,
	ERROR_CSPACE_INSUFFICIENT_RIGHTS  = 53,
	ERROR_CSPACE_FULL		  = 54,
	ERROR_MSGQUEUE_EMPTY		  = 60,
	ERROR_MSGQUEUE_FULL		  = 61,
	ERROR_STRING_TRUNCATED		  = 90,
	ERROR_STRING_REACHED_END	  = 91,
	ERROR_STRING_INVALID_FORMAT	  = 92,
	ERROR_STRING_MISSING_PLACEHOLDER  = 93,
	ERROR_STRING_MISSING_ARGUMENT	  = 94,
	ERROR_ALLOCATOR_RANGE_OVERLAPPING = 100,
	ERROR_ALLOCATOR_MEM_INUSE	  = 101,
	ERROR_MEMDB_EMPTY		  = 110,
	ERROR_MEMDB_NOT_OWNER		  = 111,
	ERROR_MEMEXTENT_MAPPINGS_FULL	  = 120,
	ERROR_EXISTING_MAPPING		  = 200
} error_t;

#define ERROR__MAX (error_t)(200)
#define ERROR__MIN (error_t)(-2)

// Bitfield: hyp_api_flags0 <uint64_t>
typedef struct hyp_api_flags0 {
	// 0         const bool partition_cspace
	// 1         const bool doorbell
	// 2         const bool msgqueue
	// 3         const bool vic
	// 4         const bool vpm
	// 5         const bool vcpu
	// 6         const bool memextent
	// 7         const bool trace_ctrl
	// 8         const bool watchdog
	// 9         const bool virtio_mmio
	// 10        const bool prng
	// 63:32,27:11 const uint64_t res0_0
	// 31:28     const scheduler_variant_t scheduler
	uint64_t bf[1];
} hyp_api_flags0_t;

#define hyp_api_flags0_default()                                               \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = { 268436735 }                                            \
	}

#define hyp_api_flags0_cast(val_0)                                             \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
hyp_api_flags0_raw(hyp_api_flags0_t bit_field);

_Atomic uint64_t *
hyp_api_flags0_atomic_ptr_raw(_Atomic hyp_api_flags0_t *ptr);

void
hyp_api_flags0_init(hyp_api_flags0_t *bit_field);

hyp_api_flags0_t
hyp_api_flags0_clean(hyp_api_flags0_t val);

bool
hyp_api_flags0_is_equal(hyp_api_flags0_t b1, hyp_api_flags0_t b2);

// Bitfield: hyp_api_flags1 <uint64_t>
typedef struct hyp_api_flags1 {
	// 63:0      const uint64_t res0_0
	uint64_t bf[1];
} hyp_api_flags1_t;

#define hyp_api_flags1_default()                                               \
	(hyp_api_flags1_t)                                                     \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define hyp_api_flags1_cast(val_0)                                             \
	(hyp_api_flags1_t)                                                     \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
hyp_api_flags1_raw(hyp_api_flags1_t bit_field);

_Atomic uint64_t *
hyp_api_flags1_atomic_ptr_raw(_Atomic hyp_api_flags1_t *ptr);

void
hyp_api_flags1_init(hyp_api_flags1_t *bit_field);

hyp_api_flags1_t
hyp_api_flags1_clean(hyp_api_flags1_t val);

bool
hyp_api_flags1_is_equal(hyp_api_flags1_t b1, hyp_api_flags1_t b2);

// Bitfield: hyp_api_flags2 <uint64_t>
typedef struct hyp_api_flags2 {
	// 63:0      const uint64_t res0_0
	uint64_t bf[1];
} hyp_api_flags2_t;

#define hyp_api_flags2_default()                                               \
	(hyp_api_flags2_t)                                                     \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define hyp_api_flags2_cast(val_0)                                             \
	(hyp_api_flags2_t)                                                     \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
hyp_api_flags2_raw(hyp_api_flags2_t bit_field);

_Atomic uint64_t *
hyp_api_flags2_atomic_ptr_raw(_Atomic hyp_api_flags2_t *ptr);

void
hyp_api_flags2_init(hyp_api_flags2_t *bit_field);

hyp_api_flags2_t
hyp_api_flags2_clean(hyp_api_flags2_t val);

bool
hyp_api_flags2_is_equal(hyp_api_flags2_t b1, hyp_api_flags2_t b2);

typedef enum hyp_variant {
	HYP_VARIANT_UNKNOWN  = 0,
	HYP_VARIANT_GUNYAH   = 72,
	HYP_VARIANT_QUALCOMM = 81
} hyp_variant_t;

#define HYP_VARIANT__MAX (hyp_variant_t)(81U)
#define HYP_VARIANT__MIN (hyp_variant_t)(0U)

// Bitfield: hyp_api_info <uint64_t>
typedef struct hyp_api_info {
	// 13:0      const uint16_t api_version
	// 14        const bool big_endian
	// 15        const bool is_64bit
	// 63:56     const hyp_variant_t variant
	uint64_t bf[1];
} hyp_api_info_t;

#define hyp_api_info_default()                                                 \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = { 5836665117072195585 }                                  \
	}

#define hyp_api_info_cast(val_0)                                               \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
hyp_api_info_raw(hyp_api_info_t bit_field);

_Atomic uint64_t *
hyp_api_info_atomic_ptr_raw(_Atomic hyp_api_info_t *ptr);

void
hyp_api_info_init(hyp_api_info_t *bit_field);

hyp_api_info_t
hyp_api_info_clean(hyp_api_info_t val);

bool
hyp_api_info_is_equal(hyp_api_info_t b1, hyp_api_info_t b2);

typedef enum pgtable_access {
	PGTABLE_ACCESS_NONE = 0,
	PGTABLE_ACCESS_X    = 1,
	PGTABLE_ACCESS_W    = 2,
	PGTABLE_ACCESS_R    = 4,
	PGTABLE_ACCESS_RX   = 5,
	PGTABLE_ACCESS_RW   = 6,
	PGTABLE_ACCESS_RWX  = 7
} pgtable_access_t;

#define PGTABLE_ACCESS__MAX (pgtable_access_t)(7U)
#define PGTABLE_ACCESS__MIN (pgtable_access_t)(0U)

typedef enum pgtable_vm_memtype {
	PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE  = 0,
	PGTABLE_VM_MEMTYPE_DEVICE_NGNRE	  = 1,
	PGTABLE_VM_MEMTYPE_DEVICE_NGRE	  = 2,
	PGTABLE_VM_MEMTYPE_DEVICE_GRE	  = 3,
	PGTABLE_VM_MEMTYPE_NORMAL_NC	  = 5,
	PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT = 6,
	PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB = 7,
	PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC = 9,
	PGTABLE_VM_MEMTYPE_NORMAL_WT	  = 10,
	PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB = 11,
	PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC = 13,
	PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT = 14,
	PGTABLE_VM_MEMTYPE_NORMAL_WB	  = 15
} pgtable_vm_memtype_t;

#define PGTABLE_VM_MEMTYPE__MAX (pgtable_vm_memtype_t)(15U)
#define PGTABLE_VM_MEMTYPE__MIN (pgtable_vm_memtype_t)(0U)

// Bitfield: memextent_mapping_attrs <uint32_t>
typedef struct memextent_mapping_attrs {
	// 2:0       pgtable_access_t user_access
	// 31:24,15:7,3 const uint64_t res_0
	// 6:4       pgtable_access_t kernel_access
	// 23:16     pgtable_vm_memtype_t memtype
	uint32_t bf[1];
} memextent_mapping_attrs_t;

#define memextent_mapping_attrs_default()                                      \
	(memextent_mapping_attrs_t)                                            \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define memextent_mapping_attrs_cast(val_0)                                    \
	(memextent_mapping_attrs_t)                                            \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
memextent_mapping_attrs_raw(memextent_mapping_attrs_t bit_field);

_Atomic uint32_t *
memextent_mapping_attrs_atomic_ptr_raw(_Atomic memextent_mapping_attrs_t *ptr);

void
memextent_mapping_attrs_init(memextent_mapping_attrs_t *bit_field);

memextent_mapping_attrs_t
memextent_mapping_attrs_clean(memextent_mapping_attrs_t val);

bool
memextent_mapping_attrs_is_equal(memextent_mapping_attrs_t b1,
				 memextent_mapping_attrs_t b2);

typedef enum memextent_memtype {
	MEMEXTENT_MEMTYPE_ANY	   = 0,
	MEMEXTENT_MEMTYPE_DEVICE   = 1,
	MEMEXTENT_MEMTYPE_UNCACHED = 2,
	MEMEXTENT_MEMTYPE_CACHED   = 3
} memextent_memtype_t;

#define MEMEXTENT_MEMTYPE__MAX (memextent_memtype_t)(3U)
#define MEMEXTENT_MEMTYPE__MIN (memextent_memtype_t)(0U)

// Bitfield: memextent_access_attrs <uint32_t>
typedef struct memextent_access_attrs {
	// 2:0       pgtable_access_t user_access
	// 31:7,3    const uint64_t res_0
	// 6:4       pgtable_access_t kernel_access
	uint32_t bf[1];
} memextent_access_attrs_t;

#define memextent_access_attrs_default()                                       \
	(memextent_access_attrs_t)                                             \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define memextent_access_attrs_cast(val_0)                                     \
	(memextent_access_attrs_t)                                             \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
memextent_access_attrs_raw(memextent_access_attrs_t bit_field);

_Atomic uint32_t *
memextent_access_attrs_atomic_ptr_raw(_Atomic memextent_access_attrs_t *ptr);

void
memextent_access_attrs_init(memextent_access_attrs_t *bit_field);

memextent_access_attrs_t
memextent_access_attrs_clean(memextent_access_attrs_t val);

bool
memextent_access_attrs_is_equal(memextent_access_attrs_t b1,
				memextent_access_attrs_t b2);

// Bitfield: memextent_attrs <uint32_t>
typedef struct memextent_attrs {
	// 2:0       pgtable_access_t access
	// 30:10,7:3 const uint64_t res_0
	// 9:8       memextent_memtype_t memtype
	// 31        bool append
	uint32_t bf[1];
} memextent_attrs_t;

#define memextent_attrs_default()                                              \
	(memextent_attrs_t)                                                    \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define memextent_attrs_cast(val_0)                                            \
	(memextent_attrs_t)                                                    \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
memextent_attrs_raw(memextent_attrs_t bit_field);

_Atomic uint32_t *
memextent_attrs_atomic_ptr_raw(_Atomic memextent_attrs_t *ptr);

void
memextent_attrs_init(memextent_attrs_t *bit_field);

memextent_attrs_t
memextent_attrs_clean(memextent_attrs_t val);

bool
memextent_attrs_is_equal(memextent_attrs_t b1, memextent_attrs_t b2);

// Bitfield: msgqueue_create_info <uint64_t>
typedef struct msgqueue_create_info {
	// 15:0      uint16_t queue_depth
	// 31:16     uint16_t max_msg_size
	uint64_t bf[1];
} msgqueue_create_info_t;

#define msgqueue_create_info_default()                                         \
	(msgqueue_create_info_t)                                               \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define msgqueue_create_info_cast(val_0)                                       \
	(msgqueue_create_info_t)                                               \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
msgqueue_create_info_raw(msgqueue_create_info_t bit_field);

_Atomic uint64_t *
msgqueue_create_info_atomic_ptr_raw(_Atomic msgqueue_create_info_t *ptr);

void
msgqueue_create_info_init(msgqueue_create_info_t *bit_field);

msgqueue_create_info_t
msgqueue_create_info_clean(msgqueue_create_info_t val);

bool
msgqueue_create_info_is_equal(msgqueue_create_info_t b1,
			      msgqueue_create_info_t b2);

// Bitfield: msgqueue_send_flags <uint32_t>
typedef struct msgqueue_send_flags {
	// 0         bool push
	uint32_t bf[1];
} msgqueue_send_flags_t;

#define msgqueue_send_flags_default()                                          \
	(msgqueue_send_flags_t)                                                \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define msgqueue_send_flags_cast(val_0)                                        \
	(msgqueue_send_flags_t)                                                \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
msgqueue_send_flags_raw(msgqueue_send_flags_t bit_field);

_Atomic uint32_t *
msgqueue_send_flags_atomic_ptr_raw(_Atomic msgqueue_send_flags_t *ptr);

void
msgqueue_send_flags_init(msgqueue_send_flags_t *bit_field);

msgqueue_send_flags_t
msgqueue_send_flags_clean(msgqueue_send_flags_t val);

bool
msgqueue_send_flags_is_equal(msgqueue_send_flags_t b1,
			     msgqueue_send_flags_t b2);

// Union of boolean fields of two msgqueue_send_flags_t values
msgqueue_send_flags_t
msgqueue_send_flags_union(msgqueue_send_flags_t b1, msgqueue_send_flags_t b2);

// Intersection of boolean fields of two msgqueue_send_flags_t values
msgqueue_send_flags_t
msgqueue_send_flags_intersection(msgqueue_send_flags_t b1,
				 msgqueue_send_flags_t b2);

// Invert all boolean fields in a msgqueue_send_flags_t value
msgqueue_send_flags_t
msgqueue_send_flags_inverse(msgqueue_send_flags_t b);

// Set difference of boolean fields of two msgqueue_send_flags_t values
msgqueue_send_flags_t
msgqueue_send_flags_difference(msgqueue_send_flags_t b1,
			       msgqueue_send_flags_t b2);

// Atomically replace a msgqueue_send_flags_t value with the union of its
// boolean fields with a given msgqueue_send_flags_t value, and return the
// previous value.
msgqueue_send_flags_t
msgqueue_send_flags_atomic_union(_Atomic msgqueue_send_flags_t *b1,
				 msgqueue_send_flags_t b2, memory_order order);

// Atomically replace a msgqueue_send_flags_t value with the intersection of its
// boolean fields with a given msgqueue_send_flags_t value, and return the
// previous value.
msgqueue_send_flags_t
msgqueue_send_flags_atomic_intersection(_Atomic msgqueue_send_flags_t *b1,
					msgqueue_send_flags_t	       b2,
					memory_order		       order);

// Atomically replace a msgqueue_send_flags_t value with the set difference of
// its boolean fields and a given msgqueue_send_flags_t value, and return the
// previous value.
msgqueue_send_flags_t
msgqueue_send_flags_atomic_difference(_Atomic msgqueue_send_flags_t *b1,
				      msgqueue_send_flags_t	     b2,
				      memory_order		     order);
typedef enum scheduler_yield_hint {
	SCHEDULER_YIELD_HINT_YIELD	     = 0,
	SCHEDULER_YIELD_HINT_YIELD_TO_THREAD = 1,
	SCHEDULER_YIELD_HINT_YIELD_LOWER     = 2
} scheduler_yield_hint_t;

#define SCHEDULER_YIELD_HINT__MAX (scheduler_yield_hint_t)(2U)
#define SCHEDULER_YIELD_HINT__MIN (scheduler_yield_hint_t)(0U)

// Bitfield: scheduler_yield_control <uint32_t>
typedef struct scheduler_yield_control {
	// 15:0      scheduler_yield_hint_t hint
	// 31        bool impl_def
	uint32_t bf[1];
} scheduler_yield_control_t;

#define scheduler_yield_control_default()                                      \
	(scheduler_yield_control_t)                                            \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define scheduler_yield_control_cast(val_0)                                    \
	(scheduler_yield_control_t)                                            \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint32_t
scheduler_yield_control_raw(scheduler_yield_control_t bit_field);

_Atomic uint32_t *
scheduler_yield_control_atomic_ptr_raw(_Atomic scheduler_yield_control_t *ptr);

void
scheduler_yield_control_init(scheduler_yield_control_t *bit_field);

scheduler_yield_control_t
scheduler_yield_control_clean(scheduler_yield_control_t val);

bool
scheduler_yield_control_is_equal(scheduler_yield_control_t b1,
				 scheduler_yield_control_t b2);

typedef int64_t sregister_t;

// Bitfield: vcpu_option_flags <uint64_t>
typedef struct vcpu_option_flags {
	// 0         bool pinned
	// 1         bool ras_error_handler
	// 2         bool amu_counting_disabled
	// 3         bool sve_allowed
	// 4         bool debug_allowed
	// 63        bool hlos_vm
	uint64_t bf[1];
} vcpu_option_flags_t;

#define vcpu_option_flags_default()                                            \
	(vcpu_option_flags_t)                                                  \
	{                                                                      \
		.bf = { 0 }                                                    \
	}

#define vcpu_option_flags_cast(val_0)                                          \
	(vcpu_option_flags_t)                                                  \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
vcpu_option_flags_raw(vcpu_option_flags_t bit_field);

_Atomic uint64_t *
vcpu_option_flags_atomic_ptr_raw(_Atomic vcpu_option_flags_t *ptr);

void
vcpu_option_flags_init(vcpu_option_flags_t *bit_field);

vcpu_option_flags_t
vcpu_option_flags_clean(vcpu_option_flags_t val);

bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2);

// Union of boolean fields of two vcpu_option_flags_t values
vcpu_option_flags_t
vcpu_option_flags_union(vcpu_option_flags_t b1, vcpu_option_flags_t b2);

// Intersection of boolean fields of two vcpu_option_flags_t values
vcpu_option_flags_t
vcpu_option_flags_intersection(vcpu_option_flags_t b1, vcpu_option_flags_t b2);

// Invert all boolean fields in a vcpu_option_flags_t value
vcpu_option_flags_t
vcpu_option_flags_inverse(vcpu_option_flags_t b);

// Set difference of boolean fields of two vcpu_option_flags_t values
vcpu_option_flags_t
vcpu_option_flags_difference(vcpu_option_flags_t b1, vcpu_option_flags_t b2);

// Atomically replace a vcpu_option_flags_t value with the union of its boolean
// fields with a given vcpu_option_flags_t value, and return the previous value.
vcpu_option_flags_t
vcpu_option_flags_atomic_union(_Atomic vcpu_option_flags_t *b1,
			       vcpu_option_flags_t b2, memory_order order);

// Atomically replace a vcpu_option_flags_t value with the intersection of its
// boolean fields with a given vcpu_option_flags_t value, and return the
// previous value.
vcpu_option_flags_t
vcpu_option_flags_atomic_intersection(_Atomic vcpu_option_flags_t *b1,
				      vcpu_option_flags_t	   b2,
				      memory_order		   order);

// Atomically replace a vcpu_option_flags_t value with the set difference of its
// boolean fields and a given vcpu_option_flags_t value, and return the previous
// value.
vcpu_option_flags_t
vcpu_option_flags_atomic_difference(_Atomic vcpu_option_flags_t *b1,
				    vcpu_option_flags_t b2, memory_order order);
typedef char *user_ptr_t;

// Bitfield: vic_option_flags <uint64_t>
typedef struct vic_option_flags {
	// 0         bool max_msis_valid
	// 63:1      uint64_t res0_0
	uint64_t bf[1];
} vic_option_flags_t;

#define vic_option_flags_default()                                             \
	(vic_option_flags_t)                                                   \
	{                                                                      \
		.bf = { 1 }                                                    \
	}

#define vic_option_flags_cast(val_0)                                           \
	(vic_option_flags_t)                                                   \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

uint64_t
vic_option_flags_raw(vic_option_flags_t bit_field);

_Atomic uint64_t *
vic_option_flags_atomic_ptr_raw(_Atomic vic_option_flags_t *ptr);

void
vic_option_flags_init(vic_option_flags_t *bit_field);

vic_option_flags_t
vic_option_flags_clean(vic_option_flags_t val);

bool
vic_option_flags_is_equal(vic_option_flags_t b1, vic_option_flags_t b2);

#include <guest_hypresult.h>

void
cap_rights_addrspace_set_attach(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_attach(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_attach(cap_rights_addrspace_t	*bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_map(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_map(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_map(cap_rights_addrspace_t	     *bit_field_dst,
			      const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_object_activate(cap_rights_addrspace_t *bit_field,
					 bool			 val);

bool
cap_rights_addrspace_get_object_activate(
	const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_object_activate(
	cap_rights_addrspace_t       *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_create(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_create(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_create(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_delete(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_delete(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_delete(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_copy(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_copy(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_copy(cap_rights_cspace_t	    *bit_field_dst,
				const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_attach(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_attach(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_attach(cap_rights_cspace_t	  *bit_field_dst,
			      const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_revoke(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_revoke(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_revoke(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_object_activate(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_object_activate(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_object_activate(cap_rights_cspace_t	   *bit_field_dst,
				       const cap_rights_cspace_t *bit_field_src);

void
cap_rights_doorbell_set_send(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_send(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_send(cap_rights_doorbell_t	    *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_receive(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_receive(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_receive(cap_rights_doorbell_t       *bit_field_dst,
				 const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_bind(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_bind(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_bind(cap_rights_doorbell_t	    *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_object_activate(cap_rights_doorbell_t *bit_field,
					bool		       val);

bool
cap_rights_doorbell_get_object_activate(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_object_activate(
	cap_rights_doorbell_t	      *bit_field_dst,
	const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_generic_set_object_activate(cap_rights_generic_t *bit_field,
				       bool		     val);

bool
cap_rights_generic_get_object_activate(const cap_rights_generic_t *bit_field);

void
cap_rights_generic_copy_object_activate(
	cap_rights_generic_t	     *bit_field_dst,
	const cap_rights_generic_t *bit_field_src);

void
cap_rights_hwirq_set_bind_vic(cap_rights_hwirq_t *bit_field, bool val);

bool
cap_rights_hwirq_get_bind_vic(const cap_rights_hwirq_t *bit_field);

void
cap_rights_hwirq_copy_bind_vic(cap_rights_hwirq_t	  *bit_field_dst,
			       const cap_rights_hwirq_t *bit_field_src);

void
cap_rights_hwirq_set_object_activate(cap_rights_hwirq_t *bit_field, bool val);

bool
cap_rights_hwirq_get_object_activate(const cap_rights_hwirq_t *bit_field);

void
cap_rights_hwirq_copy_object_activate(cap_rights_hwirq_t	 *bit_field_dst,
				      const cap_rights_hwirq_t *bit_field_src);

void
cap_rights_memextent_set_map(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_map(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_map(cap_rights_memextent_t	     *bit_field_dst,
			      const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_derive(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_derive(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_derive(cap_rights_memextent_t	*bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_attach(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_attach(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_attach(cap_rights_memextent_t	*bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_object_activate(cap_rights_memextent_t *bit_field,
					 bool			 val);

bool
cap_rights_memextent_get_object_activate(
	const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_object_activate(
	cap_rights_memextent_t       *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src);

void
cap_rights_msgqueue_set_send(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_send(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_send(cap_rights_msgqueue_t	    *bit_field_dst,
			      const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_receive(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_receive(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_receive(cap_rights_msgqueue_t       *bit_field_dst,
				 const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_bind_send(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_bind_send(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_bind_send(cap_rights_msgqueue_t	 *bit_field_dst,
				   const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_bind_receive(cap_rights_msgqueue_t *bit_field,
				     bool		    val);

bool
cap_rights_msgqueue_get_bind_receive(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_bind_receive(
	cap_rights_msgqueue_t	      *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_object_activate(cap_rights_msgqueue_t *bit_field,
					bool		       val);

bool
cap_rights_msgqueue_get_object_activate(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_object_activate(
	cap_rights_msgqueue_t	      *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_partition_set_object_create(cap_rights_partition_t *bit_field,
				       bool		       val);

bool
cap_rights_partition_get_object_create(const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_object_create(
	cap_rights_partition_t       *bit_field_dst,
	const cap_rights_partition_t *bit_field_src);

void
cap_rights_partition_set_object_activate(cap_rights_partition_t *bit_field,
					 bool			 val);

bool
cap_rights_partition_get_object_activate(
	const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_object_activate(
	cap_rights_partition_t       *bit_field_dst,
	const cap_rights_partition_t *bit_field_src);

void
cap_rights_thread_set_yield_to(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_yield_to(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_yield_to(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_power(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_power(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_power(cap_rights_thread_t	 *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_affinity(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_affinity(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_affinity(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_priority(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_priority(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_priority(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_timeslice(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_timeslice(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_timeslice(cap_rights_thread_t	     *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_lifecycle(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_lifecycle(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_lifecycle(cap_rights_thread_t	     *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_object_activate(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_object_activate(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_object_activate(cap_rights_thread_t	   *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src);

void
cap_rights_vic_set_bind_source(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_bind_source(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_bind_source(cap_rights_vic_t	 *bit_field_dst,
				const cap_rights_vic_t *bit_field_src);

void
cap_rights_vic_set_attach_vcpu(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_attach_vcpu(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_attach_vcpu(cap_rights_vic_t	 *bit_field_dst,
				const cap_rights_vic_t *bit_field_src);

void
cap_rights_vic_set_object_activate(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_object_activate(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_object_activate(cap_rights_vic_t	     *bit_field_dst,
				    const cap_rights_vic_t *bit_field_src);

void
cap_rights_vpm_group_set_attach_vcpu(cap_rights_vpm_group_t *bit_field,
				     bool		     val);

bool
cap_rights_vpm_group_get_attach_vcpu(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_attach_vcpu(
	cap_rights_vpm_group_t       *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_bind_virq(cap_rights_vpm_group_t *bit_field, bool val);

bool
cap_rights_vpm_group_get_bind_virq(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_bind_virq(cap_rights_vpm_group_t	   *bit_field_dst,
				    const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_query(cap_rights_vpm_group_t *bit_field, bool val);

bool
cap_rights_vpm_group_get_query(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_query(cap_rights_vpm_group_t       *bit_field_dst,
				const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_object_activate(cap_rights_vpm_group_t *bit_field,
					 bool			 val);

bool
cap_rights_vpm_group_get_object_activate(
	const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_object_activate(
	cap_rights_vpm_group_t       *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

bool
hyp_api_flags0_get_watchdog(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_virtio_mmio(const hyp_api_flags0_t *bit_field);

scheduler_variant_t
hyp_api_flags0_get_scheduler(const hyp_api_flags0_t *bit_field);

uint64_t
hyp_api_flags0_get_res0_0(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_doorbell(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_msgqueue(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_partition_cspace(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_trace_ctrl(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vic(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vpm(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_memextent(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_prng(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vcpu(const hyp_api_flags0_t *bit_field);

uint64_t
hyp_api_flags1_get_res0_0(const hyp_api_flags1_t *bit_field);

uint64_t
hyp_api_flags2_get_res0_0(const hyp_api_flags2_t *bit_field);

uint16_t
hyp_api_info_get_api_version(const hyp_api_info_t *bit_field);

bool
hyp_api_info_get_big_endian(const hyp_api_info_t *bit_field);

bool
hyp_api_info_get_is_64bit(const hyp_api_info_t *bit_field);

hyp_variant_t
hyp_api_info_get_variant(const hyp_api_info_t *bit_field);

void
memextent_mapping_attrs_set_user_access(memextent_mapping_attrs_t *bit_field,
					pgtable_access_t	   val);

pgtable_access_t
memextent_mapping_attrs_get_user_access(
	const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_user_access(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

void
memextent_mapping_attrs_set_kernel_access(memextent_mapping_attrs_t *bit_field,
					  pgtable_access_t	     val);

pgtable_access_t
memextent_mapping_attrs_get_kernel_access(
	const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_kernel_access(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

void
memextent_mapping_attrs_set_memtype(memextent_mapping_attrs_t *bit_field,
				    pgtable_vm_memtype_t       val);

pgtable_vm_memtype_t
memextent_mapping_attrs_get_memtype(const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_memtype(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

uint64_t
memextent_mapping_attrs_get_res_0(const memextent_mapping_attrs_t *bit_field);

void
memextent_access_attrs_set_user_access(memextent_access_attrs_t *bit_field,
				       pgtable_access_t		 val);

pgtable_access_t
memextent_access_attrs_get_user_access(
	const memextent_access_attrs_t *bit_field);

void
memextent_access_attrs_copy_user_access(
	memextent_access_attrs_t	 *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src);

void
memextent_access_attrs_set_kernel_access(memextent_access_attrs_t *bit_field,
					 pgtable_access_t	   val);

pgtable_access_t
memextent_access_attrs_get_kernel_access(
	const memextent_access_attrs_t *bit_field);

void
memextent_access_attrs_copy_kernel_access(
	memextent_access_attrs_t	 *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src);

uint64_t
memextent_access_attrs_get_res_0(const memextent_access_attrs_t *bit_field);

void
memextent_attrs_set_access(memextent_attrs_t *bit_field, pgtable_access_t val);

pgtable_access_t
memextent_attrs_get_access(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_access(memextent_attrs_t	      *bit_field_dst,
			    const memextent_attrs_t *bit_field_src);

void
memextent_attrs_set_memtype(memextent_attrs_t  *bit_field,
			    memextent_memtype_t val);

memextent_memtype_t
memextent_attrs_get_memtype(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_memtype(memextent_attrs_t       *bit_field_dst,
			     const memextent_attrs_t *bit_field_src);

void
memextent_attrs_set_append(memextent_attrs_t *bit_field, bool val);

bool
memextent_attrs_get_append(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_append(memextent_attrs_t	      *bit_field_dst,
			    const memextent_attrs_t *bit_field_src);

uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field);

void
msgqueue_create_info_set_queue_depth(msgqueue_create_info_t *bit_field,
				     uint16_t		     val);

uint16_t
msgqueue_create_info_get_queue_depth(const msgqueue_create_info_t *bit_field);

void
msgqueue_create_info_copy_queue_depth(
	msgqueue_create_info_t       *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src);

void
msgqueue_create_info_set_max_msg_size(msgqueue_create_info_t *bit_field,
				      uint16_t		      val);

uint16_t
msgqueue_create_info_get_max_msg_size(const msgqueue_create_info_t *bit_field);

void
msgqueue_create_info_copy_max_msg_size(
	msgqueue_create_info_t       *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src);

void
msgqueue_send_flags_set_push(msgqueue_send_flags_t *bit_field, bool val);

bool
msgqueue_send_flags_get_push(const msgqueue_send_flags_t *bit_field);

void
msgqueue_send_flags_copy_push(msgqueue_send_flags_t	    *bit_field_dst,
			      const msgqueue_send_flags_t *bit_field_src);

void
scheduler_yield_control_set_hint(scheduler_yield_control_t *bit_field,
				 scheduler_yield_hint_t	    val);

scheduler_yield_hint_t
scheduler_yield_control_get_hint(const scheduler_yield_control_t *bit_field);

void
scheduler_yield_control_copy_hint(
	scheduler_yield_control_t	  *bit_field_dst,
	const scheduler_yield_control_t *bit_field_src);

void
scheduler_yield_control_set_impl_def(scheduler_yield_control_t *bit_field,
				     bool			val);

bool
scheduler_yield_control_get_impl_def(const scheduler_yield_control_t *bit_field);

void
scheduler_yield_control_copy_impl_def(
	scheduler_yield_control_t	  *bit_field_dst,
	const scheduler_yield_control_t *bit_field_src);

void
vcpu_option_flags_set_pinned(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_pinned(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_pinned(vcpu_option_flags_t	  *bit_field_dst,
			      const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_ras_error_handler(vcpu_option_flags_t *bit_field,
					bool		     val);

bool
vcpu_option_flags_get_ras_error_handler(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_ras_error_handler(
	vcpu_option_flags_t	    *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_amu_counting_disabled(vcpu_option_flags_t *bit_field,
					    bool		 val);

bool
vcpu_option_flags_get_amu_counting_disabled(
	const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_amu_counting_disabled(
	vcpu_option_flags_t	    *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_sve_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_sve_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_sve_allowed(vcpu_option_flags_t       *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_hlos_vm(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_hlos_vm(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_hlos_vm(vcpu_option_flags_t	   *bit_field_dst,
			       const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_debug_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_debug_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_debug_allowed(vcpu_option_flags_t	 *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src);

void
vic_option_flags_set_max_msis_valid(vic_option_flags_t *bit_field, bool val);

bool
vic_option_flags_get_max_msis_valid(const vic_option_flags_t *bit_field);

void
vic_option_flags_copy_max_msis_valid(vic_option_flags_t	*bit_field_dst,
				     const vic_option_flags_t *bit_field_src);

void
vic_option_flags_set_res0_0(vic_option_flags_t *bit_field, uint64_t val);

uint64_t
vic_option_flags_get_res0_0(const vic_option_flags_t *bit_field);

void
vic_option_flags_copy_res0_0(vic_option_flags_t	*bit_field_dst,
			     const vic_option_flags_t *bit_field_src);
