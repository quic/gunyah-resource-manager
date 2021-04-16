// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include <hyperror.h>

typedef struct boot_env_phys_range boot_env_phys_range_t;
typedef struct boot_env_data	   boot_env_data_t;

typedef uint32_t index_t;

#define BOOT_ENV_RANGES_NUM 32
typedef uint16_t cpu_index_t;

typedef uint64_t cap_id_t;

#define CSPACE_CAP_INVALID (cap_id_t)18446744073709551615U
typedef uint32_t count_t;

#define MSGQUEUE_DELAY_UNCHANGED     (count_t)4294967295U
#define MSGQUEUE_MAX_MAX_MSG_SIZE    (count_t)1024U
#define MSGQUEUE_MAX_QUEUE_DEPTH     (count_t)256U
#define MSGQUEUE_THRESHOLD_MAXIMUM   (count_t)4294967294U
#define MSGQUEUE_THRESHOLD_UNCHANGED (count_t)4294967295U
typedef uint32_t priority_t;

#define SCHEDULER_DEFAULT_PRIORITY (priority_t)32U
typedef uint64_t nanoseconds_t;

#define SCHEDULER_DEFAULT_TIMESLICE (nanoseconds_t)5000000U
#define SCHEDULER_MAX_PRIORITY	    (priority_t)63U
#define SCHEDULER_MAX_TIMESLICE	    (nanoseconds_t)100000000U
#define SCHEDULER_MIN_PRIORITY	    (priority_t)0U
#define SCHEDULER_MIN_TIMESLICE	    (nanoseconds_t)1000000U
typedef enum scheduler_variant {
	SCHEDULER_VARIANT_TRIVIAL = 0,
	SCHEDULER_VARIANT_FPRR	  = 1
} scheduler_variant_t;

#define SCHEDULER_VARIANT__MAX (scheduler_variant_t)(1U)
#define SCHEDULER_VARIANT__MIN (scheduler_variant_t)(0U)

typedef uint16_t vmid_t;

typedef uint64_t paddr_t;

typedef uint64_t register_t;

struct boot_env_phys_range {
	paddr_t base;
	size_t	size;
};

typedef uint64_t vmaddr_t;

struct boot_env_data {
	boot_env_phys_range_t free_ranges[32];
	count_t		      free_ranges_count;
	uint8_t		      pad_to_addrspace_capid_[4];
	cap_id_t	      addrspace_capid;
	cap_id_t	      device_me_capid;
	vmaddr_t	      device_me_base;
	vmaddr_t	      entry_hlos;
	vmaddr_t	      hlos_vm_base;
	size_t		      hlos_vm_size;
	vmaddr_t	      hlos_dt_base;
	vmaddr_t	      hlos_ramfs_base;
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
	cap_id_t	      vic;
	cap_id_t	      vic_hwirq[1020];
	paddr_t		      gicd_base;
	paddr_t		      gicr_base;
};

typedef uint32_t cap_rights_t;

typedef uint32_t virq_t;

typedef enum error {
	ERROR_RETRY			  = -2,
	ERROR_UNIMPLEMENTED		  = -1,
	OK				  = 0,
	ERROR_ARGUMENT_INVALID		  = 1,
	ERROR_ARGUMENT_SIZE		  = 2,
	ERROR_ARGUMENT_ALIGNMENT	  = 3,
	ERROR_NOMEM			  = 10,
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

typedef struct hyp_api_flags0 {
	uint64_t bf[1];
} hyp_api_flags0_t;

#define hyp_api_flags0_default()                                               \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = { 268435711 }                                            \
	}

#define hyp_api_flags0_cast(val_0)                                             \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

static inline uint64_t
hyp_api_flags0_raw(hyp_api_flags0_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
hyp_api_flags0_atomic_ptr_raw(_Atomic hyp_api_flags0_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags0_t *)ptr)->bf[0];
}

static inline void
hyp_api_flags0_init(hyp_api_flags0_t *bit_field)
{
	*bit_field = hyp_api_flags0_default();
}

static inline bool
hyp_api_flags0_is_equal(hyp_api_flags0_t b1, hyp_api_flags0_t b2)
{
	return ((b1.bf[0] & 0xf0ff00ffU) == (b2.bf[0] & 0xf0ff00ffU));
}

typedef struct hyp_api_flags1 {
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

static inline uint64_t
hyp_api_flags1_raw(hyp_api_flags1_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
hyp_api_flags1_atomic_ptr_raw(_Atomic hyp_api_flags1_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags1_t *)ptr)->bf[0];
}

static inline void
hyp_api_flags1_init(hyp_api_flags1_t *bit_field)
{
	*bit_field = hyp_api_flags1_default();
}

static inline bool
hyp_api_flags1_is_equal(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

typedef struct hyp_api_flags2 {
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

static inline uint64_t
hyp_api_flags2_raw(hyp_api_flags2_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
hyp_api_flags2_atomic_ptr_raw(_Atomic hyp_api_flags2_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags2_t *)ptr)->bf[0];
}

static inline void
hyp_api_flags2_init(hyp_api_flags2_t *bit_field)
{
	*bit_field = hyp_api_flags2_default();
}

static inline bool
hyp_api_flags2_is_equal(hyp_api_flags2_t b1, hyp_api_flags2_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}
typedef enum hyp_variant {
	HYP_VARIANT_UNKNOWN = 0,
	HYP_VARIANT_GUNYAH  = 72
} hyp_variant_t;

#define HYP_VARIANT__MAX (hyp_variant_t)(72U)
#define HYP_VARIANT__MIN (hyp_variant_t)(0U)

typedef struct hyp_api_info {
	uint64_t bf[1];
} hyp_api_info_t;

#define hyp_api_info_default()                                                 \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = { 5188146770730844161 }                                  \
	}

#define hyp_api_info_cast(val_0)                                               \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = { val_0 }                                                \
	}

static inline uint64_t
hyp_api_info_raw(hyp_api_info_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
hyp_api_info_atomic_ptr_raw(_Atomic hyp_api_info_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_info_t *)ptr)->bf[0];
}

static inline void
hyp_api_info_init(hyp_api_info_t *bit_field)
{
	*bit_field = hyp_api_info_default();
}

static inline bool
hyp_api_info_is_equal(hyp_api_info_t b1, hyp_api_info_t b2)
{
	return ((b1.bf[0] & 0xff0000000000ffffU) ==
		(b2.bf[0] & 0xff0000000000ffffU));
}
typedef enum memextent_memtype {
	MEMEXTENT_MEMTYPE_ANY	   = 0,
	MEMEXTENT_MEMTYPE_DEVICE   = 1,
	MEMEXTENT_MEMTYPE_UNCACHED = 2,
	MEMEXTENT_MEMTYPE_CACHED   = 3
} memextent_memtype_t;

#define MEMEXTENT_MEMTYPE__MAX (memextent_memtype_t)(3U)
#define MEMEXTENT_MEMTYPE__MIN (memextent_memtype_t)(0U)

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

typedef struct memextent_mapping_attrs {
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

static inline uint32_t
memextent_mapping_attrs_raw(memextent_mapping_attrs_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint32_t *
memextent_mapping_attrs_atomic_ptr_raw(_Atomic memextent_mapping_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_mapping_attrs_t *)ptr)->bf[0];
}

static inline void
memextent_mapping_attrs_init(memextent_mapping_attrs_t *bit_field)
{
	*bit_field = memextent_mapping_attrs_default();
}

static inline bool
memextent_mapping_attrs_is_equal(memextent_mapping_attrs_t b1,
				 memextent_mapping_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

typedef struct memextent_access_attrs {
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

static inline uint32_t
memextent_access_attrs_raw(memextent_access_attrs_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint32_t *
memextent_access_attrs_atomic_ptr_raw(_Atomic memextent_access_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_access_attrs_t *)ptr)->bf[0];
}

static inline void
memextent_access_attrs_init(memextent_access_attrs_t *bit_field)
{
	*bit_field = memextent_access_attrs_default();
}

static inline bool
memextent_access_attrs_is_equal(memextent_access_attrs_t b1,
				memextent_access_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

typedef struct memextent_attrs {
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

static inline uint32_t
memextent_attrs_raw(memextent_attrs_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint32_t *
memextent_attrs_atomic_ptr_raw(_Atomic memextent_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_attrs_t *)ptr)->bf[0];
}

static inline void
memextent_attrs_init(memextent_attrs_t *bit_field)
{
	*bit_field = memextent_attrs_default();
}

static inline bool
memextent_attrs_is_equal(memextent_attrs_t b1, memextent_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

typedef struct msgqueue_create_info {
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

static inline uint64_t
msgqueue_create_info_raw(msgqueue_create_info_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
msgqueue_create_info_atomic_ptr_raw(_Atomic msgqueue_create_info_t *ptr)
{
	return (_Atomic uint64_t *)&((msgqueue_create_info_t *)ptr)->bf[0];
}

static inline void
msgqueue_create_info_init(msgqueue_create_info_t *bit_field)
{
	*bit_field = msgqueue_create_info_default();
}

static inline bool
msgqueue_create_info_is_equal(msgqueue_create_info_t b1,
			      msgqueue_create_info_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}
typedef int64_t sregister_t;

typedef struct vcpu_option_flags {
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

static inline uint64_t
vcpu_option_flags_raw(vcpu_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

static inline _Atomic uint64_t *
vcpu_option_flags_atomic_ptr_raw(_Atomic vcpu_option_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vcpu_option_flags_t *)ptr)->bf[0];
}

static inline void
vcpu_option_flags_init(vcpu_option_flags_t *bit_field)
{
	*bit_field = vcpu_option_flags_default();
}

static inline bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}
typedef char *user_ptr_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"

HYPTYPES_DECLARE_RESULT_(bool, bool)
HYPTYPES_DECLARE_RESULT_PTR_(bool, bool)
HYPTYPES_DECLARE_RESULT_(uint8, uint8_t)
HYPTYPES_DECLARE_RESULT_PTR_(uint8, uint8_t)
HYPTYPES_DECLARE_RESULT_(uint16, uint16_t)
HYPTYPES_DECLARE_RESULT_PTR_(uint16, uint16_t)
HYPTYPES_DECLARE_RESULT_(uint32, uint32_t)
HYPTYPES_DECLARE_RESULT_PTR_(uint32, uint32_t)
HYPTYPES_DECLARE_RESULT_(uint64, uint64_t)
HYPTYPES_DECLARE_RESULT_PTR_(uint64, uint64_t)
HYPTYPES_DECLARE_RESULT_(uintptr, uintptr_t)
HYPTYPES_DECLARE_RESULT_PTR_(uintptr, uintptr_t)
HYPTYPES_DECLARE_RESULT_(sint8, int8_t)
HYPTYPES_DECLARE_RESULT_PTR_(sint8, int8_t)
HYPTYPES_DECLARE_RESULT_(sint16, int16_t)
HYPTYPES_DECLARE_RESULT_PTR_(sint16, int16_t)
HYPTYPES_DECLARE_RESULT_(sint32, int32_t)
HYPTYPES_DECLARE_RESULT_PTR_(sint32, int32_t)
HYPTYPES_DECLARE_RESULT_(sint64, int64_t)
HYPTYPES_DECLARE_RESULT_PTR_(sint64, int64_t)
HYPTYPES_DECLARE_RESULT_(sintptr, intptr_t)
HYPTYPES_DECLARE_RESULT_PTR_(sintptr, intptr_t)
HYPTYPES_DECLARE_RESULT_(char, char)
HYPTYPES_DECLARE_RESULT_PTR_(char, char)
HYPTYPES_DECLARE_RESULT_(size, size_t)
HYPTYPES_DECLARE_RESULT_PTR_(size, size_t)
HYPTYPES_DECLARE_RESULT_PTR_(void, void)
HYPTYPES_DECLARE_RESULT(index)
HYPTYPES_DECLARE_RESULT_PTR(index)
HYPTYPES_DECLARE_RESULT(cpu_index)
HYPTYPES_DECLARE_RESULT_PTR(cpu_index)
HYPTYPES_DECLARE_RESULT(cap_id)
HYPTYPES_DECLARE_RESULT_PTR(cap_id)
HYPTYPES_DECLARE_RESULT(count)
HYPTYPES_DECLARE_RESULT_PTR(count)
HYPTYPES_DECLARE_RESULT(priority)
HYPTYPES_DECLARE_RESULT_PTR(priority)
HYPTYPES_DECLARE_RESULT(nanoseconds)
HYPTYPES_DECLARE_RESULT_PTR(nanoseconds)
HYPTYPES_DECLARE_RESULT(scheduler_variant)
HYPTYPES_DECLARE_RESULT_PTR(scheduler_variant)
HYPTYPES_DECLARE_RESULT(vmid)
HYPTYPES_DECLARE_RESULT_PTR(vmid)
HYPTYPES_DECLARE_RESULT(paddr)
HYPTYPES_DECLARE_RESULT_PTR(paddr)
HYPTYPES_DECLARE_RESULT(register)
HYPTYPES_DECLARE_RESULT_PTR(register)
HYPTYPES_DECLARE_RESULT(boot_env_phys_range)
HYPTYPES_DECLARE_RESULT_PTR(boot_env_phys_range)
HYPTYPES_DECLARE_RESULT(vmaddr)
HYPTYPES_DECLARE_RESULT_PTR(vmaddr)
HYPTYPES_DECLARE_RESULT(boot_env_data)
HYPTYPES_DECLARE_RESULT_PTR(boot_env_data)
HYPTYPES_DECLARE_RESULT(cap_rights)
HYPTYPES_DECLARE_RESULT_PTR(cap_rights)
HYPTYPES_DECLARE_RESULT(virq)
HYPTYPES_DECLARE_RESULT_PTR(virq)
HYPTYPES_DECLARE_RESULT(error)
HYPTYPES_DECLARE_RESULT_PTR(error)
HYPTYPES_DECLARE_RESULT(hyp_api_flags0)
HYPTYPES_DECLARE_RESULT_PTR(hyp_api_flags0)
HYPTYPES_DECLARE_RESULT(hyp_api_flags1)
HYPTYPES_DECLARE_RESULT_PTR(hyp_api_flags1)
HYPTYPES_DECLARE_RESULT(hyp_api_flags2)
HYPTYPES_DECLARE_RESULT_PTR(hyp_api_flags2)
HYPTYPES_DECLARE_RESULT(hyp_variant)
HYPTYPES_DECLARE_RESULT_PTR(hyp_variant)
HYPTYPES_DECLARE_RESULT(hyp_api_info)
HYPTYPES_DECLARE_RESULT_PTR(hyp_api_info)
HYPTYPES_DECLARE_RESULT(memextent_memtype)
HYPTYPES_DECLARE_RESULT_PTR(memextent_memtype)
HYPTYPES_DECLARE_RESULT(pgtable_access)
HYPTYPES_DECLARE_RESULT_PTR(pgtable_access)
HYPTYPES_DECLARE_RESULT(pgtable_vm_memtype)
HYPTYPES_DECLARE_RESULT_PTR(pgtable_vm_memtype)
HYPTYPES_DECLARE_RESULT(memextent_mapping_attrs)
HYPTYPES_DECLARE_RESULT_PTR(memextent_mapping_attrs)
HYPTYPES_DECLARE_RESULT(memextent_access_attrs)
HYPTYPES_DECLARE_RESULT_PTR(memextent_access_attrs)
HYPTYPES_DECLARE_RESULT(memextent_attrs)
HYPTYPES_DECLARE_RESULT_PTR(memextent_attrs)
HYPTYPES_DECLARE_RESULT(msgqueue_create_info)
HYPTYPES_DECLARE_RESULT_PTR(msgqueue_create_info)
HYPTYPES_DECLARE_RESULT(sregister)
HYPTYPES_DECLARE_RESULT_PTR(sregister)
HYPTYPES_DECLARE_RESULT(vcpu_option_flags)
HYPTYPES_DECLARE_RESULT_PTR(vcpu_option_flags)
HYPTYPES_DECLARE_RESULT(user_ptr)
HYPTYPES_DECLARE_RESULT_PTR(user_ptr)
#pragma clang diagnostic pop

static inline uint8_t
hyp_api_flags0_get_hyp_variant_reserved(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 16) & (uint64_t)0xff) << 0;
	return (uint8_t)val;
}

static inline scheduler_variant_t
hyp_api_flags0_get_scheduler(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 28) & (uint64_t)0xf) << 0;
	return (scheduler_variant_t)val;
}

static inline bool
hyp_api_flags0_get_doorbell(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 1) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_msgqueue(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 2) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_partition_cspace(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_trace_ctrl(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 7) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_vic(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 3) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_vpm(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 4) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_memextent(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 6) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_flags0_get_vcpu(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 5) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline uint64_t
hyp_api_flags1_get_res0_0(const hyp_api_flags1_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0xffffffffffffffff) << 0;
	return (uint64_t)val;
}

static inline uint64_t
hyp_api_flags2_get_res0_0(const hyp_api_flags2_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0xffffffffffffffff) << 0;
	return (uint64_t)val;
}

static inline uint16_t
hyp_api_info_get_api_version(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0x3fff) << 0;
	return (uint16_t)val;
}

static inline bool
hyp_api_info_get_big_endian(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 14) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline bool
hyp_api_info_get_is_64bit(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 15) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline hyp_variant_t
hyp_api_info_get_variant(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 56) & (uint64_t)0xff) << 0;
	return (hyp_variant_t)val;
}

static inline void
memextent_mapping_attrs_set_user_access(memextent_mapping_attrs_t *bit_field,
					pgtable_access_t	   val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xfffffff8U;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x7U) << 0;
	bf[0] = tmp;
}

static inline pgtable_access_t
memextent_mapping_attrs_get_user_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint32_t)0x7) << 0;
	return (pgtable_access_t)val;
}

static inline void
memextent_mapping_attrs_set_kernel_access(memextent_mapping_attrs_t *bit_field,
					  pgtable_access_t	     val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xffffff8fU;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x7U) << 4;
	bf[0] = tmp;
}

static inline pgtable_access_t
memextent_mapping_attrs_get_kernel_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 4) & (uint32_t)0x7) << 0;
	return (pgtable_access_t)val;
}

static inline void
memextent_mapping_attrs_set_memtype(memextent_mapping_attrs_t *bit_field,
				    pgtable_vm_memtype_t       val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xff00ffffU;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0xffU) << 16;
	bf[0] = tmp;
}

static inline pgtable_vm_memtype_t
memextent_mapping_attrs_get_memtype(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 16) & (uint32_t)0xff) << 0;
	return (pgtable_vm_memtype_t)val;
}

static inline uint64_t
memextent_mapping_attrs_get_res_0(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 3) & (uint32_t)0x1) << 0;
	val |= ((tmp >> 7) & (uint32_t)0x1ff) << 1;
	val |= ((tmp >> 24) & (uint32_t)0xff) << 10;
	return (uint64_t)val;
}

static inline void
memextent_access_attrs_set_user_access(memextent_access_attrs_t *bit_field,
				       pgtable_access_t		 val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xfffffff8U;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x7U) << 0;
	bf[0] = tmp;
}

static inline pgtable_access_t
memextent_access_attrs_get_user_access(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint32_t)0x7) << 0;
	return (pgtable_access_t)val;
}

static inline void
memextent_access_attrs_set_kernel_access(memextent_access_attrs_t *bit_field,
					 pgtable_access_t	   val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xffffff8fU;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x7U) << 4;
	bf[0] = tmp;
}

static inline pgtable_access_t
memextent_access_attrs_get_kernel_access(
	const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 4) & (uint32_t)0x7) << 0;
	return (pgtable_access_t)val;
}

static inline uint64_t
memextent_access_attrs_get_res_0(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 3) & (uint32_t)0x1) << 0;
	val |= ((tmp >> 7) & (uint32_t)0x1ffffff) << 1;
	return (uint64_t)val;
}

static inline void
memextent_attrs_set_access(memextent_attrs_t *bit_field, pgtable_access_t val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xfffffff8U;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x7U) << 0;
	bf[0] = tmp;
}

static inline pgtable_access_t
memextent_attrs_get_access(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint32_t)0x7) << 0;
	return (pgtable_access_t)val;
}

static inline void
memextent_attrs_set_memtype(memextent_attrs_t * bit_field,
			    memextent_memtype_t val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0xfffffcffU;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x3U) << 8;
	bf[0] = tmp;
}

static inline memextent_memtype_t
memextent_attrs_get_memtype(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 8) & (uint32_t)0x3) << 0;
	return (memextent_memtype_t)val;
}

static inline void
memextent_attrs_set_append(memextent_attrs_t *bit_field, bool val)
{
	uint32_t *bf  = (uint32_t *)bit_field;
	uint32_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint32_t)0x7fffffffU;
	tmp |= ((((uint32_t)val) >> 0) & (uint32_t)0x1U) << 31;
	bf[0] = tmp;
}

static inline bool
memextent_attrs_get_append(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 31) & (uint32_t)0x1) << 0;
	return (bool)val;
}

static inline uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	uint32_t	tmp;
	const uint32_t *bf = (const uint32_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 3) & (uint32_t)0x1f) << 0;
	val |= ((tmp >> 10) & (uint32_t)0x1fffff) << 5;
	return (uint64_t)val;
}

static inline void
msgqueue_create_info_set_queue_depth(msgqueue_create_info_t *bit_field,
				     uint16_t		     val)
{
	uint64_t *bf  = (uint64_t *)bit_field;
	uint64_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint64_t)0xffffffffffff0000U;
	tmp |= ((((uint64_t)val) >> 0) & (uint64_t)0xffffU) << 0;
	bf[0] = tmp;
}

static inline uint16_t
msgqueue_create_info_get_queue_depth(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0xffff) << 0;
	return (uint16_t)val;
}

static inline void
msgqueue_create_info_set_max_msg_size(msgqueue_create_info_t *bit_field,
				      uint16_t		      val)
{
	uint64_t *bf  = (uint64_t *)bit_field;
	uint64_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint64_t)0xffffffff0000ffffU;
	tmp |= ((((uint64_t)val) >> 0) & (uint64_t)0xffffU) << 16;
	bf[0] = tmp;
}

static inline uint16_t
msgqueue_create_info_get_max_msg_size(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 16) & (uint64_t)0xffff) << 0;
	return (uint16_t)val;
}

static inline void
vcpu_option_flags_set_pinned(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t *bf  = (uint64_t *)bit_field;
	uint64_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint64_t)0xfffffffffffffffeU;
	tmp |= ((((uint64_t)val) >> 0) & (uint64_t)0x1U) << 0;
	bf[0] = tmp;
}

static inline bool
vcpu_option_flags_get_pinned(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 0) & (uint64_t)0x1) << 0;
	return (bool)val;
}

static inline void
vcpu_option_flags_set_res0_0(vcpu_option_flags_t *bit_field, uint64_t val)
{
	uint64_t *bf  = (uint64_t *)bit_field;
	uint64_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint64_t)0x8000000000000001U;
	tmp |= ((((uint64_t)val) >> 0) & (uint64_t)0x3fffffffffffffffU) << 1;
	bf[0] = tmp;
}

static inline uint64_t
vcpu_option_flags_get_res0_0(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 1) & (uint64_t)0x3fffffffffffffff) << 0;
	return (uint64_t)val;
}

static inline void
vcpu_option_flags_set_hlos_vm(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t *bf  = (uint64_t *)bit_field;
	uint64_t  tmp = 0;

	tmp = bf[0];
	tmp &= (uint64_t)0x7fffffffffffffffU;
	tmp |= ((((uint64_t)val) >> 0) & (uint64_t)0x1U) << 63;
	bf[0] = tmp;
}

static inline bool
vcpu_option_flags_get_hlos_vm(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	uint64_t	tmp;
	const uint64_t *bf = (const uint64_t *)&bit_field->bf[0];

	tmp = bf[0];
	val |= ((tmp >> 63) & (uint64_t)0x1) << 0;
	return (bool)val;
}
