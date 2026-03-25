// Automatically generated. Do not modify.
//
// Copyright © Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HYPTYPES_H_
#define HYPTYPES_H_

#include <limits.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

typedef union addrspace_attach_vdevice_flags_u addrspace_attach_vdevice_flags_t;
typedef struct addrspace_info_area_entry_data_info_b
	addrspace_info_area_entry_data_info_t;
typedef struct addrspace_info_area_entry_flags_b
	addrspace_info_area_entry_flags_t;
typedef struct addrspace_info_area_entry_type_b addrspace_info_area_entry_type_t;
typedef struct addrspace_map_flags_b	      addrspace_map_flags_t;
typedef struct addrspace_modify_pages_flags_b addrspace_modify_pages_flags_t;
typedef struct allocator_memattr_b	      allocator_memattr_t;
typedef struct allocator_stats_s	      allocator_stats_t;
typedef struct allocator_stats_info_b	      allocator_stats_info_t;
typedef struct boot_env_phys_range_s	      boot_env_phys_range_t;
typedef struct cap_rights_addrspace_b	      cap_rights_addrspace_t;
typedef struct cap_rights_cspace_b	      cap_rights_cspace_t;
typedef struct cap_rights_doorbell_b	      cap_rights_doorbell_t;
typedef struct cap_rights_generic_b	      cap_rights_generic_t;
typedef struct cap_rights_gicv3_its_b	      cap_rights_gicv3_its_t;
typedef struct cap_rights_hwirq_b	      cap_rights_hwirq_t;
typedef struct cap_rights_memextent_b	      cap_rights_memextent_t;
typedef struct cap_rights_msgqueue_b	      cap_rights_msgqueue_t;
typedef struct cap_rights_partition_b	      cap_rights_partition_t;
typedef struct cap_rights_pci_function_b      cap_rights_pci_function_t;
typedef struct cap_rights_pci_host_b	      cap_rights_pci_host_t;
typedef struct cap_rights_power_b	      cap_rights_power_t;
typedef struct cap_rights_smmuv3_b	      cap_rights_smmuv3_t;
typedef struct cap_rights_thread_b	      cap_rights_thread_t;
typedef struct cap_rights_vgic_its_b	      cap_rights_vgic_its_t;
typedef struct cap_rights_vic_b		      cap_rights_vic_t;
typedef struct cap_rights_virtio_backend_b    cap_rights_virtio_backend_t;
typedef struct cap_rights_virtio_iommu_b      cap_rights_virtio_iommu_t;
typedef struct cap_rights_vpci_b	      cap_rights_vpci_t;
typedef struct cap_rights_vpm_group_b	      cap_rights_vpm_group_t;
typedef struct cap_rights_vrtc_b	      cap_rights_vrtc_t;
typedef struct cap_rights_vsmmuv2_b	      cap_rights_vsmmuv2_t;
typedef struct cap_rights_watchdog_b	      cap_rights_watchdog_t;
typedef struct hyp_api_flags0_b		      hyp_api_flags0_t;
typedef struct hyp_api_flags1_b		      hyp_api_flags1_t;
typedef struct hyp_api_flags2_b		      hyp_api_flags2_t;
typedef struct hyp_api_info_b		      hyp_api_info_t;
typedef struct memextent_access_attrs_b	      memextent_access_attrs_t;
typedef struct memextent_attrs_b	      memextent_attrs_t;
typedef struct memextent_donate_options_b     memextent_donate_options_t;
typedef struct memextent_mapping_attrs_b      memextent_mapping_attrs_t;
typedef struct memextent_modify_flags_b	      memextent_modify_flags_t;
typedef struct msgqueue_create_info_b	      msgqueue_create_info_t;
typedef struct msgqueue_send_flags_b	      msgqueue_send_flags_t;
typedef struct partition_donate_flags_b	      partition_donate_flags_t;
typedef struct partition_query_flags_b	      partition_query_flags_t;
typedef struct pci_capability_access_flags_b  pci_capability_access_flags_t;
typedef struct pci_function_option_flags_b    pci_function_option_flags_t;
typedef struct pci_host_option_flags_b	      pci_host_option_flags_t;
typedef struct pci_responder_id_b	      pci_responder_id_t;
typedef struct rm_env_data_hdr_s	      rm_env_data_hdr_t;
typedef struct root_env_mmio_range_descriptor_s root_env_mmio_range_descriptor_t;
typedef struct root_env_mmio_range_properties_b root_env_mmio_range_properties_t;
typedef struct rt_env_data_s		       rt_env_data_t;
typedef struct scheduler_yield_control_b       scheduler_yield_control_t;
typedef struct sdei_error_flags_b	       sdei_error_flags_t;
typedef struct smccc_function_id_b	       smccc_function_id_t;
typedef struct smccc_vendor_hyp_function_id_b  smccc_vendor_hyp_function_id_t;
typedef struct vcpu_option_flags_b	       vcpu_option_flags_t;
typedef struct vcpu_poweroff_flags_b	       vcpu_poweroff_flags_t;
typedef struct vcpu_poweron_flags_b	       vcpu_poweron_flags_t;
typedef struct vcpu_run_poweroff_flags_b       vcpu_run_poweroff_flags_t;
typedef struct vgic_gicr_attach_flags_b	       vgic_gicr_attach_flags_t;
typedef struct vic_msi_source_config_b	       vic_msi_source_config_t;
typedef struct vic_option_flags_b	       vic_option_flags_t;
typedef struct virtio_backend_interface_type_b virtio_backend_interface_type_t;
typedef struct virtio_backend_interrupt_perqueue_b
	virtio_backend_interrupt_perqueue_t;
typedef struct virtio_backend_memextent_layout_b
					      virtio_backend_memextent_layout_t;
typedef struct virtio_backend_notify_flags_b  virtio_backend_notify_flags_t;
typedef struct virtio_backend_notify_reason_b virtio_backend_notify_reason_t;
typedef union virtio_backend_notify_status_u  virtio_backend_notify_status_t;
typedef struct virtio_backend_option_flags_b  virtio_backend_option_flags_t;
typedef struct virtio_interrupt_b	      virtio_interrupt_t;
typedef struct virtio_iommu_options_b	      virtio_iommu_options_t;
typedef struct virtio_status_b		      virtio_status_t;
typedef struct vpci_aperture_b		      vpci_aperture_t;
typedef struct vpci_option_flags_b	      vpci_option_flags_t;
typedef struct vpm_group_option_flags_b	      vpm_group_option_flags_t;
typedef struct watchdog_bind_option_flags_b   watchdog_bind_option_flags_t;
typedef struct watchdog_option_flags_b	      watchdog_option_flags_t;

#define ADDRSPACE_INFO_AREA_ID_OWNER_INDEX (uint32_t)0U // 0x0
typedef uint16_t cpu_index_t;
#define CPU_INDEX_INVALID (cpu_index_t)65535U // 0xffff
typedef uint64_t cap_id_t;
#define CSPACE_CAP_INVALID (cap_id_t)18446744073709551615U // 0xffffffffffffffff
typedef uint32_t count_t;
#define MSGQUEUE_DELAY_UNCHANGED     (count_t)4294967295U  // 0xffffffff
#define MSGQUEUE_MAX_MAX_MSG_SIZE    (count_t)1024U	   // 0x400
#define MSGQUEUE_MAX_QUEUE_DEPTH     (count_t)256U	   // 0x100
#define MSGQUEUE_THRESHOLD_MAXIMUM   (count_t)4294967294U  // 0xfffffffe
#define MSGQUEUE_THRESHOLD_UNCHANGED (count_t)4294967295U  // 0xffffffff
#define RM_ENV_DATA_SIGNATURE	     (uint32_t)1380795716U // 0x524d4544
#define RM_ENV_DATA_VERSION	     (uint16_t)4096U	   // 0x1000
#define ROOTVM_ENV_DATA_SIGNATURE    (uint32_t)1162696274U // 0x454d5652
#define ROOTVM_ENV_DATA_VERSION	     (uint16_t)4096U	   // 0x1000
typedef uint32_t priority_t;
#define ROOTVM_PRIORITY		   (priority_t)32U // 0x20
#define SCHEDULER_DEFAULT_PRIORITY (priority_t)32U // 0x20
#define SCHEDULER_MAX_PRIORITY	   (priority_t)63U // 0x3f
typedef uint64_t nanoseconds_t;
#define SCHEDULER_MAX_TIMESLICE	 (nanoseconds_t)100000000U // 0x5f5e100
#define SCHEDULER_MIN_PRIORITY	 (priority_t)0U		   // 0x0
#define SCHEDULER_MIN_TIMESLICE	 (nanoseconds_t)100000U	   // 0x186a0
#define SMCCC_GUNYAH_UID0	 (uint64_t)3448755649U	   // 0xcd8fd5c1
#define SMCCC_GUNYAH_UID1	 (uint64_t)3680457636U	   // 0xdb5f53a4
#define SMCCC_GUNYAH_UID2	 (uint64_t)919496082U	   // 0x36ce6592
#define SMCCC_GUNYAH_UID3	 (uint64_t)341785959U	   // 0x145f3d67
#define SMCCC_UNKNOWN_FUNCTION32 (uint32_t)4294967295U	   // 0xffffffff
#define SMCCC_UNKNOWN_FUNCTION64                                               \
	(uint64_t)18446744073709551615U	   // 0xffffffffffffffff
#define SMCCC_VERSION	  (uint32_t)65539U // 0x10003
#define VCPU_MAX_PRIORITY (priority_t)62U  // 0x3e
typedef uint32_t index_t;
#define VGIC_ITS_MAX_NUM (index_t)16U // 0x10
typedef uint32_t virq_t;
#define VIRQ_INVALID  (virq_t)4294967295U // 0xffffffff
#define VIRQ_SDEI_BIT (virq_t)2147483648U // 0x80000000

typedef enum addrspace_access_type_e {
	ADDRSPACE_ACCESS_TYPE_READ    = 0,
	ADDRSPACE_ACCESS_TYPE_WRITE   = 1,
	ADDRSPACE_ACCESS_TYPE_EXECUTE = 2
} addrspace_access_type_t;

#define ADDRSPACE_ACCESS_TYPE__MAX ADDRSPACE_ACCESS_TYPE_EXECUTE
#define ADDRSPACE_ACCESS_TYPE__MIN ADDRSPACE_ACCESS_TYPE_READ

// Bitfield: vgic_gicr_attach_flags <uint64_t>
typedef struct vgic_gicr_attach_flags_b {
	// 0         bool last_valid
	// 1         bool last
	uint64_t bf[1];
} vgic_gicr_attach_flags_t;

#define vgic_gicr_attach_flags_default()                                       \
	(vgic_gicr_attach_flags_t)                                             \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vgic_gicr_attach_flags_cast(val_0)                                     \
	(vgic_gicr_attach_flags_t)                                             \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vgic_gicr_attach_flags_raw(vgic_gicr_attach_flags_t bit_field);

void
vgic_gicr_attach_flags_init(vgic_gicr_attach_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_clean(vgic_gicr_attach_flags_t bit_field);

bool
vgic_gicr_attach_flags_is_equal(vgic_gicr_attach_flags_t b1,
				vgic_gicr_attach_flags_t b2);

bool
vgic_gicr_attach_flags_is_empty(vgic_gicr_attach_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vgic_gicr_attach_flags_is_clean(vgic_gicr_attach_flags_t bit_field);

// Union of boolean fields of two vgic_gicr_attach_flags_t values
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_union(vgic_gicr_attach_flags_t b1,
			     vgic_gicr_attach_flags_t b2);

// Intersection of boolean fields of two vgic_gicr_attach_flags_t values
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_intersection(vgic_gicr_attach_flags_t b1,
				    vgic_gicr_attach_flags_t b2);

// Invert all boolean fields in a vgic_gicr_attach_flags_t value
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_inverse(vgic_gicr_attach_flags_t b);

// Set difference of boolean fields of two vgic_gicr_attach_flags_t values
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_difference(vgic_gicr_attach_flags_t b1,
				  vgic_gicr_attach_flags_t b2);

// Atomically replace a vgic_gicr_attach_flags_t value with the union of its
// boolean fields with a given vgic_gicr_attach_flags_t value, and return the
// previous value.
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_union(_Atomic vgic_gicr_attach_flags_t *b1,
				    vgic_gicr_attach_flags_t	      b2,
				    memory_order		      order);

// Atomically replace a vgic_gicr_attach_flags_t value with the intersection of
// its boolean fields with a given vgic_gicr_attach_flags_t value, and return
// the previous value.
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_intersection(_Atomic vgic_gicr_attach_flags_t *b1,
					   vgic_gicr_attach_flags_t	     b2,
					   memory_order order);

// Atomically replace a vgic_gicr_attach_flags_t value with the set difference
// of its boolean fields and a given vgic_gicr_attach_flags_t value, and return
// the previous value.
vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_difference(_Atomic vgic_gicr_attach_flags_t *b1,
					 vgic_gicr_attach_flags_t	   b2,
					 memory_order order);

union addrspace_attach_vdevice_flags_u {
	uint64_t		 raw;
	vgic_gicr_attach_flags_t vgic_gicr;
};

// Bitfield: addrspace_info_area_entry_data_info <uint64_t>
typedef struct addrspace_info_area_entry_data_info_b {
	// 31:0      size_t size
	// 63:32     size_t alignment
	uint64_t bf[1];
} addrspace_info_area_entry_data_info_t;

#define addrspace_info_area_entry_data_info_default()                          \
	(addrspace_info_area_entry_data_info_t)                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define addrspace_info_area_entry_data_info_cast(val_0)                        \
	(addrspace_info_area_entry_data_info_t)                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
addrspace_info_area_entry_data_info_raw(
	addrspace_info_area_entry_data_info_t bit_field);

void
addrspace_info_area_entry_data_info_init(
	addrspace_info_area_entry_data_info_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
addrspace_info_area_entry_data_info_t
addrspace_info_area_entry_data_info_clean(
	addrspace_info_area_entry_data_info_t bit_field);

bool
addrspace_info_area_entry_data_info_is_equal(
	addrspace_info_area_entry_data_info_t b1,
	addrspace_info_area_entry_data_info_t b2);

bool
addrspace_info_area_entry_data_info_is_empty(
	addrspace_info_area_entry_data_info_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
addrspace_info_area_entry_data_info_is_clean(
	addrspace_info_area_entry_data_info_t bit_field);

// Bitfield: addrspace_info_area_entry_flags <uint32_t>
typedef struct addrspace_info_area_entry_flags_b {
	// 31        bool valid
	uint32_t bf[1];
} addrspace_info_area_entry_flags_t;

#define addrspace_info_area_entry_flags_default()                              \
	(addrspace_info_area_entry_flags_t)                                    \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define addrspace_info_area_entry_flags_cast(val_0)                            \
	(addrspace_info_area_entry_flags_t)                                    \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
addrspace_info_area_entry_flags_raw(addrspace_info_area_entry_flags_t bit_field);

void
addrspace_info_area_entry_flags_init(
	addrspace_info_area_entry_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_clean(
	addrspace_info_area_entry_flags_t bit_field);

bool
addrspace_info_area_entry_flags_is_equal(addrspace_info_area_entry_flags_t b1,
					 addrspace_info_area_entry_flags_t b2);

bool
addrspace_info_area_entry_flags_is_empty(
	addrspace_info_area_entry_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
addrspace_info_area_entry_flags_is_clean(
	addrspace_info_area_entry_flags_t bit_field);

// Union of boolean fields of two addrspace_info_area_entry_flags_t values
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_union(addrspace_info_area_entry_flags_t b1,
				      addrspace_info_area_entry_flags_t b2);

// Intersection of boolean fields of two addrspace_info_area_entry_flags_t
// values
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_intersection(
	addrspace_info_area_entry_flags_t b1,
	addrspace_info_area_entry_flags_t b2);

// Invert all boolean fields in a addrspace_info_area_entry_flags_t value
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_inverse(addrspace_info_area_entry_flags_t b);

// Set difference of boolean fields of two addrspace_info_area_entry_flags_t
// values
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_difference(addrspace_info_area_entry_flags_t b1,
					   addrspace_info_area_entry_flags_t b2);

// Atomically replace a addrspace_info_area_entry_flags_t value with the union
// of its boolean fields with a given addrspace_info_area_entry_flags_t value,
// and return the previous value.
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_union(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order);

// Atomically replace a addrspace_info_area_entry_flags_t value with the
// intersection of its boolean fields with a given
// addrspace_info_area_entry_flags_t value, and return the previous value.
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_intersection(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order);

// Atomically replace a addrspace_info_area_entry_flags_t value with the set
// difference of its boolean fields and a given
// addrspace_info_area_entry_flags_t value, and return the previous value.
addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_difference(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order);

typedef enum addrspace_info_area_id_owner_e {
	ADDRSPACE_INFO_AREA_ID_OWNER_INVALID = 0,
	ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH  = 1,
	ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM  = 2,
	ADDRSPACE_INFO_AREA_ID_OWNER_RM	     = 3,
	ADDRSPACE_INFO_AREA_ID_OWNER_QCRM    = 16,
	ADDRSPACE_INFO_AREA_ID_OWNER_DEV     = 65535
} addrspace_info_area_id_owner_t;

#define ADDRSPACE_INFO_AREA_ID_OWNER__MAX ADDRSPACE_INFO_AREA_ID_OWNER_DEV
#define ADDRSPACE_INFO_AREA_ID_OWNER__MIN ADDRSPACE_INFO_AREA_ID_OWNER_INVALID

// Bitfield: addrspace_info_area_entry_type <uint32_t>
typedef struct addrspace_info_area_entry_type_b {
	// 15:0      uint32_t id
	// 31:16     addrspace_info_area_id_owner_t owner
	uint32_t bf[1];
} addrspace_info_area_entry_type_t;

#define addrspace_info_area_entry_type_default()                               \
	(addrspace_info_area_entry_type_t)                                     \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define addrspace_info_area_entry_type_cast(val_0)                             \
	(addrspace_info_area_entry_type_t)                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
addrspace_info_area_entry_type_raw(addrspace_info_area_entry_type_t bit_field);

void
addrspace_info_area_entry_type_init(addrspace_info_area_entry_type_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
addrspace_info_area_entry_type_t
addrspace_info_area_entry_type_clean(addrspace_info_area_entry_type_t bit_field);

bool
addrspace_info_area_entry_type_is_equal(addrspace_info_area_entry_type_t b1,
					addrspace_info_area_entry_type_t b2);

bool
addrspace_info_area_entry_type_is_empty(
	addrspace_info_area_entry_type_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
addrspace_info_area_entry_type_is_clean(
	addrspace_info_area_entry_type_t bit_field);

// Bitfield: addrspace_map_flags <uint32_t>
typedef struct addrspace_map_flags_b {
	// 0         bool partial
	// 1         bool private
	// 2         bool vmmio
	// 3         bool whole_extent
	// 31        bool no_sync
	uint32_t bf[1];
} addrspace_map_flags_t;

#define addrspace_map_flags_default()                                          \
	(addrspace_map_flags_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define addrspace_map_flags_cast(val_0)                                        \
	(addrspace_map_flags_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
addrspace_map_flags_raw(addrspace_map_flags_t bit_field);

void
addrspace_map_flags_init(addrspace_map_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
addrspace_map_flags_t
addrspace_map_flags_clean(addrspace_map_flags_t bit_field);

bool
addrspace_map_flags_is_equal(addrspace_map_flags_t b1,
			     addrspace_map_flags_t b2);

bool
addrspace_map_flags_is_empty(addrspace_map_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
addrspace_map_flags_is_clean(addrspace_map_flags_t bit_field);

// Union of boolean fields of two addrspace_map_flags_t values
addrspace_map_flags_t
addrspace_map_flags_union(addrspace_map_flags_t b1, addrspace_map_flags_t b2);

// Intersection of boolean fields of two addrspace_map_flags_t values
addrspace_map_flags_t
addrspace_map_flags_intersection(addrspace_map_flags_t b1,
				 addrspace_map_flags_t b2);

// Invert all boolean fields in a addrspace_map_flags_t value
addrspace_map_flags_t
addrspace_map_flags_inverse(addrspace_map_flags_t b);

// Set difference of boolean fields of two addrspace_map_flags_t values
addrspace_map_flags_t
addrspace_map_flags_difference(addrspace_map_flags_t b1,
			       addrspace_map_flags_t b2);

// Atomically replace a addrspace_map_flags_t value with the union of its
// boolean fields with a given addrspace_map_flags_t value, and return the
// previous value.
addrspace_map_flags_t
addrspace_map_flags_atomic_union(_Atomic addrspace_map_flags_t *b1,
				 addrspace_map_flags_t b2, memory_order order);

// Atomically replace a addrspace_map_flags_t value with the intersection of its
// boolean fields with a given addrspace_map_flags_t value, and return the
// previous value.
addrspace_map_flags_t
addrspace_map_flags_atomic_intersection(_Atomic addrspace_map_flags_t *b1,
					addrspace_map_flags_t	       b2,
					memory_order		       order);

// Atomically replace a addrspace_map_flags_t value with the set difference of
// its boolean fields and a given addrspace_map_flags_t value, and return the
// previous value.
addrspace_map_flags_t
addrspace_map_flags_atomic_difference(_Atomic addrspace_map_flags_t *b1,
				      addrspace_map_flags_t	     b2,
				      memory_order		     order);

// Bitfield: addrspace_modify_pages_flags <uint32_t>
typedef struct addrspace_modify_pages_flags_b {
	// 0         bool unlock
	// 2         bool no_sync_unlock
	// 3         bool do_not_sanitise
	uint32_t bf[1];
} addrspace_modify_pages_flags_t;

#define addrspace_modify_pages_flags_default()                                 \
	(addrspace_modify_pages_flags_t)                                       \
	{                                                                      \
		.bf = { 0x2U }                                                 \
	}

#define addrspace_modify_pages_flags_cast(val_0)                               \
	(addrspace_modify_pages_flags_t)                                       \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
addrspace_modify_pages_flags_raw(addrspace_modify_pages_flags_t bit_field);

void
addrspace_modify_pages_flags_init(addrspace_modify_pages_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_clean(addrspace_modify_pages_flags_t bit_field);

bool
addrspace_modify_pages_flags_is_equal(addrspace_modify_pages_flags_t b1,
				      addrspace_modify_pages_flags_t b2);

bool
addrspace_modify_pages_flags_is_empty(addrspace_modify_pages_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
addrspace_modify_pages_flags_is_clean(addrspace_modify_pages_flags_t bit_field);

// Union of boolean fields of two addrspace_modify_pages_flags_t values
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_union(addrspace_modify_pages_flags_t b1,
				   addrspace_modify_pages_flags_t b2);

// Intersection of boolean fields of two addrspace_modify_pages_flags_t values
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_intersection(addrspace_modify_pages_flags_t b1,
					  addrspace_modify_pages_flags_t b2);

// Invert all boolean fields in a addrspace_modify_pages_flags_t value
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_inverse(addrspace_modify_pages_flags_t b);

// Set difference of boolean fields of two addrspace_modify_pages_flags_t values
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_difference(addrspace_modify_pages_flags_t b1,
					addrspace_modify_pages_flags_t b2);

// Atomically replace a addrspace_modify_pages_flags_t value with the union of
// its boolean fields with a given addrspace_modify_pages_flags_t value, and
// return the previous value.
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_union(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order);

// Atomically replace a addrspace_modify_pages_flags_t value with the
// intersection of its boolean fields with a given
// addrspace_modify_pages_flags_t value, and return the previous value.
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_intersection(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order);

// Atomically replace a addrspace_modify_pages_flags_t value with the set
// difference of its boolean fields and a given addrspace_modify_pages_flags_t
// value, and return the previous value.
addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_difference(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order);

typedef enum addrspace_range_configure_op_e {
	ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO	    = 0,
	ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO   = 1,
	ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE    = 2,
	ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE = 3
} addrspace_range_configure_op_t;

#define ADDRSPACE_RANGE_CONFIGURE_OP__MAX                                      \
	ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE
#define ADDRSPACE_RANGE_CONFIGURE_OP__MIN ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO

typedef enum addrspace_resume_action_e {
	ADDRSPACE_RESUME_ACTION_DEFAULT = 0,
	ADDRSPACE_RESUME_ACTION_RETRY	= 1,
	ADDRSPACE_RESUME_ACTION_FAULT	= 2
} addrspace_resume_action_t;

#define ADDRSPACE_RESUME_ACTION__MAX ADDRSPACE_RESUME_ACTION_FAULT
#define ADDRSPACE_RESUME_ACTION__MIN ADDRSPACE_RESUME_ACTION_DEFAULT

typedef enum allocator_memtype_e {
	ALLOCATOR_MEMTYPE_HYPERVISOR	= 0,
	ALLOCATOR_MEMTYPE_VM_PAGE_TABLE = 1,
	ALLOCATOR_MEMTYPE_TZ_FFI	= 2
} allocator_memtype_t;

#define ALLOCATOR_MEMTYPE__MAX ALLOCATOR_MEMTYPE_TZ_FFI
#define ALLOCATOR_MEMTYPE__MIN ALLOCATOR_MEMTYPE_HYPERVISOR

// Bitfield: allocator_memattr <uint16_t>
typedef struct allocator_memattr_b {
	// 3:0       allocator_memtype_t type
	uint16_t bf[1];
} allocator_memattr_t;

#define allocator_memattr_default()                                            \
	(allocator_memattr_t)                                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define allocator_memattr_cast(val_0)                                          \
	(allocator_memattr_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint16_t
allocator_memattr_raw(allocator_memattr_t bit_field);

void
allocator_memattr_init(allocator_memattr_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
allocator_memattr_t
allocator_memattr_clean(allocator_memattr_t bit_field);

bool
allocator_memattr_is_equal(allocator_memattr_t b1, allocator_memattr_t b2);

bool
allocator_memattr_is_empty(allocator_memattr_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
allocator_memattr_is_clean(allocator_memattr_t bit_field);

// Bitfield: allocator_stats_info <uint32_t>
typedef struct allocator_stats_info_b {
	// 7:0       const uint8_t version
	uint32_t bf[1];
} allocator_stats_info_t;

#define allocator_stats_info_default()                                         \
	(allocator_stats_info_t)                                               \
	{                                                                      \
		.bf = { 0x1U }                                                 \
	}

#define allocator_stats_info_cast(val_0)                                       \
	(allocator_stats_info_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
allocator_stats_info_raw(allocator_stats_info_t bit_field);

void
allocator_stats_info_init(allocator_stats_info_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
allocator_stats_info_t
allocator_stats_info_clean(allocator_stats_info_t bit_field);

bool
allocator_stats_info_is_equal(allocator_stats_info_t b1,
			      allocator_stats_info_t b2);

bool
allocator_stats_info_is_empty(allocator_stats_info_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
allocator_stats_info_is_clean(allocator_stats_info_t bit_field);

struct allocator_stats_s {
	allocator_stats_info_t info;
	uint8_t		       pad_to_total_[4];
	size_t		       total;
	size_t		       allocated;
	size_t		       reserved;
	size_t		       largest_free;
};

typedef uint64_t paddr_t;

struct boot_env_phys_range_s {
	paddr_t base;
	size_t	size;
};

// Bitfield: cap_rights_addrspace <uint32_t>
typedef struct cap_rights_addrspace_b {
	// 0         bool attach
	// 1         bool map
	// 2         bool lookup
	// 3         bool configure_range
	// 4         bool map_protected
	// 5         bool modify_protected
	// 6         bool add_info
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_addrspace_t;

#define cap_rights_addrspace_default()                                         \
	(cap_rights_addrspace_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_addrspace_cast(val_0)                                       \
	(cap_rights_addrspace_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_addrspace_raw(cap_rights_addrspace_t bit_field);

void
cap_rights_addrspace_init(cap_rights_addrspace_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_addrspace_t
cap_rights_addrspace_clean(cap_rights_addrspace_t bit_field);

bool
cap_rights_addrspace_is_equal(cap_rights_addrspace_t b1,
			      cap_rights_addrspace_t b2);

bool
cap_rights_addrspace_is_empty(cap_rights_addrspace_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_addrspace_is_clean(cap_rights_addrspace_t bit_field);

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
typedef struct cap_rights_cspace_b {
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
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_cspace_cast(val_0)                                          \
	(cap_rights_cspace_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_cspace_raw(cap_rights_cspace_t bit_field);

void
cap_rights_cspace_init(cap_rights_cspace_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_cspace_t
cap_rights_cspace_clean(cap_rights_cspace_t bit_field);

bool
cap_rights_cspace_is_equal(cap_rights_cspace_t b1, cap_rights_cspace_t b2);

bool
cap_rights_cspace_is_empty(cap_rights_cspace_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_cspace_is_clean(cap_rights_cspace_t bit_field);

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
typedef struct cap_rights_doorbell_b {
	// 0         bool send
	// 1         bool receive
	// 2         bool bind
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_doorbell_t;

#define cap_rights_doorbell_default()                                          \
	(cap_rights_doorbell_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_doorbell_cast(val_0)                                        \
	(cap_rights_doorbell_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_doorbell_raw(cap_rights_doorbell_t bit_field);

void
cap_rights_doorbell_init(cap_rights_doorbell_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_doorbell_t
cap_rights_doorbell_clean(cap_rights_doorbell_t bit_field);

bool
cap_rights_doorbell_is_equal(cap_rights_doorbell_t b1,
			     cap_rights_doorbell_t b2);

bool
cap_rights_doorbell_is_empty(cap_rights_doorbell_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_doorbell_is_clean(cap_rights_doorbell_t bit_field);

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
typedef struct cap_rights_generic_b {
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_generic_t;

#define cap_rights_generic_default()                                           \
	(cap_rights_generic_t)                                                 \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_generic_cast(val_0)                                         \
	(cap_rights_generic_t)                                                 \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_generic_raw(cap_rights_generic_t bit_field);

void
cap_rights_generic_init(cap_rights_generic_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_generic_t
cap_rights_generic_clean(cap_rights_generic_t bit_field);

bool
cap_rights_generic_is_equal(cap_rights_generic_t b1, cap_rights_generic_t b2);

bool
cap_rights_generic_is_empty(cap_rights_generic_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_generic_is_clean(cap_rights_generic_t bit_field);

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

// Bitfield: cap_rights_gicv3_its <uint32_t>
typedef struct cap_rights_gicv3_its_b {
	// 0         bool bind_device
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_gicv3_its_t;

#define cap_rights_gicv3_its_default()                                         \
	(cap_rights_gicv3_its_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_gicv3_its_cast(val_0)                                       \
	(cap_rights_gicv3_its_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_gicv3_its_raw(cap_rights_gicv3_its_t bit_field);

void
cap_rights_gicv3_its_init(cap_rights_gicv3_its_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_gicv3_its_t
cap_rights_gicv3_its_clean(cap_rights_gicv3_its_t bit_field);

bool
cap_rights_gicv3_its_is_equal(cap_rights_gicv3_its_t b1,
			      cap_rights_gicv3_its_t b2);

bool
cap_rights_gicv3_its_is_empty(cap_rights_gicv3_its_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_gicv3_its_is_clean(cap_rights_gicv3_its_t bit_field);

// Union of boolean fields of two cap_rights_gicv3_its_t values
cap_rights_gicv3_its_t
cap_rights_gicv3_its_union(cap_rights_gicv3_its_t b1,
			   cap_rights_gicv3_its_t b2);

// Intersection of boolean fields of two cap_rights_gicv3_its_t values
cap_rights_gicv3_its_t
cap_rights_gicv3_its_intersection(cap_rights_gicv3_its_t b1,
				  cap_rights_gicv3_its_t b2);

// Invert all boolean fields in a cap_rights_gicv3_its_t value
cap_rights_gicv3_its_t
cap_rights_gicv3_its_inverse(cap_rights_gicv3_its_t b);

// Set difference of boolean fields of two cap_rights_gicv3_its_t values
cap_rights_gicv3_its_t
cap_rights_gicv3_its_difference(cap_rights_gicv3_its_t b1,
				cap_rights_gicv3_its_t b2);

// Atomically replace a cap_rights_gicv3_its_t value with the union of its
// boolean fields with a given cap_rights_gicv3_its_t value, and return the
// previous value.
cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_union(_Atomic cap_rights_gicv3_its_t *b1,
				  cap_rights_gicv3_its_t	  b2,
				  memory_order			  order);

// Atomically replace a cap_rights_gicv3_its_t value with the intersection of
// its boolean fields with a given cap_rights_gicv3_its_t value, and return the
// previous value.
cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_intersection(_Atomic cap_rights_gicv3_its_t *b1,
					 cap_rights_gicv3_its_t		 b2,
					 memory_order			 order);

// Atomically replace a cap_rights_gicv3_its_t value with the set difference of
// its boolean fields and a given cap_rights_gicv3_its_t value, and return the
// previous value.
cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_difference(_Atomic cap_rights_gicv3_its_t *b1,
				       cap_rights_gicv3_its_t	       b2,
				       memory_order		       order);

// Bitfield: cap_rights_hwirq <uint32_t>
typedef struct cap_rights_hwirq_b {
	// 1         bool bind_vic
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_hwirq_t;

#define cap_rights_hwirq_default()                                             \
	(cap_rights_hwirq_t)                                                   \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_hwirq_cast(val_0)                                           \
	(cap_rights_hwirq_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_hwirq_raw(cap_rights_hwirq_t bit_field);

void
cap_rights_hwirq_init(cap_rights_hwirq_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_hwirq_t
cap_rights_hwirq_clean(cap_rights_hwirq_t bit_field);

bool
cap_rights_hwirq_is_equal(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2);

bool
cap_rights_hwirq_is_empty(cap_rights_hwirq_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_hwirq_is_clean(cap_rights_hwirq_t bit_field);

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
typedef struct cap_rights_memextent_b {
	// 0         bool map
	// 1         bool derive
	// 2         bool attach
	// 3         bool lookup
	// 4         bool donate
	// 5         bool protected_host
	// 6         bool protected_guest
	// 7         bool map_private
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_memextent_t;

#define cap_rights_memextent_default()                                         \
	(cap_rights_memextent_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_memextent_cast(val_0)                                       \
	(cap_rights_memextent_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_memextent_raw(cap_rights_memextent_t bit_field);

void
cap_rights_memextent_init(cap_rights_memextent_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_memextent_t
cap_rights_memextent_clean(cap_rights_memextent_t bit_field);

bool
cap_rights_memextent_is_equal(cap_rights_memextent_t b1,
			      cap_rights_memextent_t b2);

bool
cap_rights_memextent_is_empty(cap_rights_memextent_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_memextent_is_clean(cap_rights_memextent_t bit_field);

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
typedef struct cap_rights_msgqueue_b {
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
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_msgqueue_cast(val_0)                                        \
	(cap_rights_msgqueue_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_msgqueue_raw(cap_rights_msgqueue_t bit_field);

void
cap_rights_msgqueue_init(cap_rights_msgqueue_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_msgqueue_t
cap_rights_msgqueue_clean(cap_rights_msgqueue_t bit_field);

bool
cap_rights_msgqueue_is_equal(cap_rights_msgqueue_t b1,
			     cap_rights_msgqueue_t b2);

bool
cap_rights_msgqueue_is_empty(cap_rights_msgqueue_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_msgqueue_is_clean(cap_rights_msgqueue_t bit_field);

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
typedef struct cap_rights_partition_b {
	// 0         bool object_create
	// 1         bool donate
	// 2         bool query
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_partition_t;

#define cap_rights_partition_default()                                         \
	(cap_rights_partition_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_partition_cast(val_0)                                       \
	(cap_rights_partition_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_partition_raw(cap_rights_partition_t bit_field);

void
cap_rights_partition_init(cap_rights_partition_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_partition_t
cap_rights_partition_clean(cap_rights_partition_t bit_field);

bool
cap_rights_partition_is_equal(cap_rights_partition_t b1,
			      cap_rights_partition_t b2);

bool
cap_rights_partition_is_empty(cap_rights_partition_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_partition_is_clean(cap_rights_partition_t bit_field);

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

// Bitfield: cap_rights_pci_function <uint32_t>
typedef struct cap_rights_pci_function_b {
	// 0         bool passthrough
	// 1         bool attach
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_pci_function_t;

#define cap_rights_pci_function_default()                                      \
	(cap_rights_pci_function_t)                                            \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_pci_function_cast(val_0)                                    \
	(cap_rights_pci_function_t)                                            \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_pci_function_raw(cap_rights_pci_function_t bit_field);

void
cap_rights_pci_function_init(cap_rights_pci_function_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_pci_function_t
cap_rights_pci_function_clean(cap_rights_pci_function_t bit_field);

bool
cap_rights_pci_function_is_equal(cap_rights_pci_function_t b1,
				 cap_rights_pci_function_t b2);

bool
cap_rights_pci_function_is_empty(cap_rights_pci_function_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_pci_function_is_clean(cap_rights_pci_function_t bit_field);

// Union of boolean fields of two cap_rights_pci_function_t values
cap_rights_pci_function_t
cap_rights_pci_function_union(cap_rights_pci_function_t b1,
			      cap_rights_pci_function_t b2);

// Intersection of boolean fields of two cap_rights_pci_function_t values
cap_rights_pci_function_t
cap_rights_pci_function_intersection(cap_rights_pci_function_t b1,
				     cap_rights_pci_function_t b2);

// Invert all boolean fields in a cap_rights_pci_function_t value
cap_rights_pci_function_t
cap_rights_pci_function_inverse(cap_rights_pci_function_t b);

// Set difference of boolean fields of two cap_rights_pci_function_t values
cap_rights_pci_function_t
cap_rights_pci_function_difference(cap_rights_pci_function_t b1,
				   cap_rights_pci_function_t b2);

// Atomically replace a cap_rights_pci_function_t value with the union of its
// boolean fields with a given cap_rights_pci_function_t value, and return the
// previous value.
cap_rights_pci_function_t
cap_rights_pci_function_atomic_union(_Atomic cap_rights_pci_function_t *b1,
				     cap_rights_pci_function_t		b2,
				     memory_order			order);

// Atomically replace a cap_rights_pci_function_t value with the intersection of
// its boolean fields with a given cap_rights_pci_function_t value, and return
// the previous value.
cap_rights_pci_function_t
cap_rights_pci_function_atomic_intersection(
	_Atomic cap_rights_pci_function_t *b1, cap_rights_pci_function_t b2,
	memory_order order);

// Atomically replace a cap_rights_pci_function_t value with the set difference
// of its boolean fields and a given cap_rights_pci_function_t value, and return
// the previous value.
cap_rights_pci_function_t
cap_rights_pci_function_atomic_difference(_Atomic cap_rights_pci_function_t *b1,
					  cap_rights_pci_function_t	     b2,
					  memory_order order);

// Bitfield: cap_rights_pci_host <uint32_t>
typedef struct cap_rights_pci_host_b {
	// 0         bool create_function
	// 1         bool set_lockdown
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_pci_host_t;

#define cap_rights_pci_host_default()                                          \
	(cap_rights_pci_host_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_pci_host_cast(val_0)                                        \
	(cap_rights_pci_host_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_pci_host_raw(cap_rights_pci_host_t bit_field);

void
cap_rights_pci_host_init(cap_rights_pci_host_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_pci_host_t
cap_rights_pci_host_clean(cap_rights_pci_host_t bit_field);

bool
cap_rights_pci_host_is_equal(cap_rights_pci_host_t b1,
			     cap_rights_pci_host_t b2);

bool
cap_rights_pci_host_is_empty(cap_rights_pci_host_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_pci_host_is_clean(cap_rights_pci_host_t bit_field);

// Union of boolean fields of two cap_rights_pci_host_t values
cap_rights_pci_host_t
cap_rights_pci_host_union(cap_rights_pci_host_t b1, cap_rights_pci_host_t b2);

// Intersection of boolean fields of two cap_rights_pci_host_t values
cap_rights_pci_host_t
cap_rights_pci_host_intersection(cap_rights_pci_host_t b1,
				 cap_rights_pci_host_t b2);

// Invert all boolean fields in a cap_rights_pci_host_t value
cap_rights_pci_host_t
cap_rights_pci_host_inverse(cap_rights_pci_host_t b);

// Set difference of boolean fields of two cap_rights_pci_host_t values
cap_rights_pci_host_t
cap_rights_pci_host_difference(cap_rights_pci_host_t b1,
			       cap_rights_pci_host_t b2);

// Atomically replace a cap_rights_pci_host_t value with the union of its
// boolean fields with a given cap_rights_pci_host_t value, and return the
// previous value.
cap_rights_pci_host_t
cap_rights_pci_host_atomic_union(_Atomic cap_rights_pci_host_t *b1,
				 cap_rights_pci_host_t b2, memory_order order);

// Atomically replace a cap_rights_pci_host_t value with the intersection of its
// boolean fields with a given cap_rights_pci_host_t value, and return the
// previous value.
cap_rights_pci_host_t
cap_rights_pci_host_atomic_intersection(_Atomic cap_rights_pci_host_t *b1,
					cap_rights_pci_host_t	       b2,
					memory_order		       order);

// Atomically replace a cap_rights_pci_host_t value with the set difference of
// its boolean fields and a given cap_rights_pci_host_t value, and return the
// previous value.
cap_rights_pci_host_t
cap_rights_pci_host_atomic_difference(_Atomic cap_rights_pci_host_t *b1,
				      cap_rights_pci_host_t	     b2,
				      memory_order		     order);

// Bitfield: cap_rights_power <uint32_t>
typedef struct cap_rights_power_b {
	// 0         bool system_suspend
	// 1         bool cpu_suspend
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_power_t;

#define cap_rights_power_default()                                             \
	(cap_rights_power_t)                                                   \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_power_cast(val_0)                                           \
	(cap_rights_power_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_power_raw(cap_rights_power_t bit_field);

void
cap_rights_power_init(cap_rights_power_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_power_t
cap_rights_power_clean(cap_rights_power_t bit_field);

bool
cap_rights_power_is_equal(cap_rights_power_t b1, cap_rights_power_t b2);

bool
cap_rights_power_is_empty(cap_rights_power_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_power_is_clean(cap_rights_power_t bit_field);

// Union of boolean fields of two cap_rights_power_t values
cap_rights_power_t
cap_rights_power_union(cap_rights_power_t b1, cap_rights_power_t b2);

// Intersection of boolean fields of two cap_rights_power_t values
cap_rights_power_t
cap_rights_power_intersection(cap_rights_power_t b1, cap_rights_power_t b2);

// Invert all boolean fields in a cap_rights_power_t value
cap_rights_power_t
cap_rights_power_inverse(cap_rights_power_t b);

// Set difference of boolean fields of two cap_rights_power_t values
cap_rights_power_t
cap_rights_power_difference(cap_rights_power_t b1, cap_rights_power_t b2);

// Atomically replace a cap_rights_power_t value with the union of its boolean
// fields with a given cap_rights_power_t value, and return the previous value.
cap_rights_power_t
cap_rights_power_atomic_union(_Atomic cap_rights_power_t *b1,
			      cap_rights_power_t b2, memory_order order);

// Atomically replace a cap_rights_power_t value with the intersection of its
// boolean fields with a given cap_rights_power_t value, and return the previous
// value.
cap_rights_power_t
cap_rights_power_atomic_intersection(_Atomic cap_rights_power_t *b1,
				     cap_rights_power_t b2, memory_order order);

// Atomically replace a cap_rights_power_t value with the set difference of its
// boolean fields and a given cap_rights_power_t value, and return the previous
// value.
cap_rights_power_t
cap_rights_power_atomic_difference(_Atomic cap_rights_power_t *b1,
				   cap_rights_power_t b2, memory_order order);

// Bitfield: cap_rights_smmuv3 <uint32_t>
typedef struct cap_rights_smmuv3_b {
	// 0         bool configure
	// 1         bool manage_streams
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_smmuv3_t;

#define cap_rights_smmuv3_default()                                            \
	(cap_rights_smmuv3_t)                                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_smmuv3_cast(val_0)                                          \
	(cap_rights_smmuv3_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_smmuv3_raw(cap_rights_smmuv3_t bit_field);

void
cap_rights_smmuv3_init(cap_rights_smmuv3_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_smmuv3_t
cap_rights_smmuv3_clean(cap_rights_smmuv3_t bit_field);

bool
cap_rights_smmuv3_is_equal(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2);

bool
cap_rights_smmuv3_is_empty(cap_rights_smmuv3_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_smmuv3_is_clean(cap_rights_smmuv3_t bit_field);

// Union of boolean fields of two cap_rights_smmuv3_t values
cap_rights_smmuv3_t
cap_rights_smmuv3_union(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2);

// Intersection of boolean fields of two cap_rights_smmuv3_t values
cap_rights_smmuv3_t
cap_rights_smmuv3_intersection(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2);

// Invert all boolean fields in a cap_rights_smmuv3_t value
cap_rights_smmuv3_t
cap_rights_smmuv3_inverse(cap_rights_smmuv3_t b);

// Set difference of boolean fields of two cap_rights_smmuv3_t values
cap_rights_smmuv3_t
cap_rights_smmuv3_difference(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2);

// Atomically replace a cap_rights_smmuv3_t value with the union of its boolean
// fields with a given cap_rights_smmuv3_t value, and return the previous value.
cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_union(_Atomic cap_rights_smmuv3_t *b1,
			       cap_rights_smmuv3_t b2, memory_order order);

// Atomically replace a cap_rights_smmuv3_t value with the intersection of its
// boolean fields with a given cap_rights_smmuv3_t value, and return the
// previous value.
cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_intersection(_Atomic cap_rights_smmuv3_t *b1,
				      cap_rights_smmuv3_t	   b2,
				      memory_order		   order);

// Atomically replace a cap_rights_smmuv3_t value with the set difference of its
// boolean fields and a given cap_rights_smmuv3_t value, and return the previous
// value.
cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_difference(_Atomic cap_rights_smmuv3_t *b1,
				    cap_rights_smmuv3_t b2, memory_order order);
typedef uint32_t cap_rights_t;

// Bitfield: cap_rights_thread <uint32_t>
typedef struct cap_rights_thread_b {
	// 0         bool power
	// 1         bool affinity
	// 2         bool priority
	// 3         bool timeslice
	// 4         bool yield_to
	// 5         bool bind_virq
	// 6         bool state
	// 7         bool lifecycle
	// 8         bool write_context
	// 9         bool disable
	// 10        bool bind_local_virq
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_thread_t;

#define cap_rights_thread_default()                                            \
	(cap_rights_thread_t)                                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_thread_cast(val_0)                                          \
	(cap_rights_thread_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_thread_raw(cap_rights_thread_t bit_field);

void
cap_rights_thread_init(cap_rights_thread_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_thread_t
cap_rights_thread_clean(cap_rights_thread_t bit_field);

bool
cap_rights_thread_is_equal(cap_rights_thread_t b1, cap_rights_thread_t b2);

bool
cap_rights_thread_is_empty(cap_rights_thread_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_thread_is_clean(cap_rights_thread_t bit_field);

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

// Bitfield: cap_rights_vgic_its <uint32_t>
typedef struct cap_rights_vgic_its_b {
	// 0         bool bind_vic
	// 1         bool attach_addrspace
	// 2         bool bind_devices
	// 3         bool unbind_devices
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vgic_its_t;

#define cap_rights_vgic_its_default()                                          \
	(cap_rights_vgic_its_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vgic_its_cast(val_0)                                        \
	(cap_rights_vgic_its_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vgic_its_raw(cap_rights_vgic_its_t bit_field);

void
cap_rights_vgic_its_init(cap_rights_vgic_its_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vgic_its_t
cap_rights_vgic_its_clean(cap_rights_vgic_its_t bit_field);

bool
cap_rights_vgic_its_is_equal(cap_rights_vgic_its_t b1,
			     cap_rights_vgic_its_t b2);

bool
cap_rights_vgic_its_is_empty(cap_rights_vgic_its_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vgic_its_is_clean(cap_rights_vgic_its_t bit_field);

// Union of boolean fields of two cap_rights_vgic_its_t values
cap_rights_vgic_its_t
cap_rights_vgic_its_union(cap_rights_vgic_its_t b1, cap_rights_vgic_its_t b2);

// Intersection of boolean fields of two cap_rights_vgic_its_t values
cap_rights_vgic_its_t
cap_rights_vgic_its_intersection(cap_rights_vgic_its_t b1,
				 cap_rights_vgic_its_t b2);

// Invert all boolean fields in a cap_rights_vgic_its_t value
cap_rights_vgic_its_t
cap_rights_vgic_its_inverse(cap_rights_vgic_its_t b);

// Set difference of boolean fields of two cap_rights_vgic_its_t values
cap_rights_vgic_its_t
cap_rights_vgic_its_difference(cap_rights_vgic_its_t b1,
			       cap_rights_vgic_its_t b2);

// Atomically replace a cap_rights_vgic_its_t value with the union of its
// boolean fields with a given cap_rights_vgic_its_t value, and return the
// previous value.
cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_union(_Atomic cap_rights_vgic_its_t *b1,
				 cap_rights_vgic_its_t b2, memory_order order);

// Atomically replace a cap_rights_vgic_its_t value with the intersection of its
// boolean fields with a given cap_rights_vgic_its_t value, and return the
// previous value.
cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_intersection(_Atomic cap_rights_vgic_its_t *b1,
					cap_rights_vgic_its_t	       b2,
					memory_order		       order);

// Atomically replace a cap_rights_vgic_its_t value with the set difference of
// its boolean fields and a given cap_rights_vgic_its_t value, and return the
// previous value.
cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_difference(_Atomic cap_rights_vgic_its_t *b1,
				      cap_rights_vgic_its_t	     b2,
				      memory_order		     order);

// Bitfield: cap_rights_vic <uint32_t>
typedef struct cap_rights_vic_b {
	// 0         bool bind_source
	// 1         bool attach_vcpu
	// 2         bool attach_vdevice
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vic_t;

#define cap_rights_vic_default()                                               \
	(cap_rights_vic_t)                                                     \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vic_cast(val_0)                                             \
	(cap_rights_vic_t)                                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vic_raw(cap_rights_vic_t bit_field);

void
cap_rights_vic_init(cap_rights_vic_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vic_t
cap_rights_vic_clean(cap_rights_vic_t bit_field);

bool
cap_rights_vic_is_equal(cap_rights_vic_t b1, cap_rights_vic_t b2);

bool
cap_rights_vic_is_empty(cap_rights_vic_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vic_is_clean(cap_rights_vic_t bit_field);

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

// Bitfield: cap_rights_virtio_backend <uint32_t>
typedef struct cap_rights_virtio_backend_b {
	// 0         bool bind_virq
	// 1         bool bind_mmio_frontend_virq
	// 2         bool assert_virq
	// 3         bool config
	// 4         bool bind_vpci
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_virtio_backend_t;

#define cap_rights_virtio_backend_default()                                    \
	(cap_rights_virtio_backend_t)                                          \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_virtio_backend_cast(val_0)                                  \
	(cap_rights_virtio_backend_t)                                          \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_virtio_backend_raw(cap_rights_virtio_backend_t bit_field);

void
cap_rights_virtio_backend_init(cap_rights_virtio_backend_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_virtio_backend_t
cap_rights_virtio_backend_clean(cap_rights_virtio_backend_t bit_field);

bool
cap_rights_virtio_backend_is_equal(cap_rights_virtio_backend_t b1,
				   cap_rights_virtio_backend_t b2);

bool
cap_rights_virtio_backend_is_empty(cap_rights_virtio_backend_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_virtio_backend_is_clean(cap_rights_virtio_backend_t bit_field);

// Union of boolean fields of two cap_rights_virtio_backend_t values
cap_rights_virtio_backend_t
cap_rights_virtio_backend_union(cap_rights_virtio_backend_t b1,
				cap_rights_virtio_backend_t b2);

// Intersection of boolean fields of two cap_rights_virtio_backend_t values
cap_rights_virtio_backend_t
cap_rights_virtio_backend_intersection(cap_rights_virtio_backend_t b1,
				       cap_rights_virtio_backend_t b2);

// Invert all boolean fields in a cap_rights_virtio_backend_t value
cap_rights_virtio_backend_t
cap_rights_virtio_backend_inverse(cap_rights_virtio_backend_t b);

// Set difference of boolean fields of two cap_rights_virtio_backend_t values
cap_rights_virtio_backend_t
cap_rights_virtio_backend_difference(cap_rights_virtio_backend_t b1,
				     cap_rights_virtio_backend_t b2);

// Atomically replace a cap_rights_virtio_backend_t value with the union of its
// boolean fields with a given cap_rights_virtio_backend_t value, and return the
// previous value.
cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_union(_Atomic cap_rights_virtio_backend_t *b1,
				       cap_rights_virtio_backend_t	    b2,
				       memory_order order);

// Atomically replace a cap_rights_virtio_backend_t value with the intersection
// of its boolean fields with a given cap_rights_virtio_backend_t value, and
// return the previous value.
cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_intersection(
	_Atomic cap_rights_virtio_backend_t *b1, cap_rights_virtio_backend_t b2,
	memory_order order);

// Atomically replace a cap_rights_virtio_backend_t value with the set
// difference of its boolean fields and a given cap_rights_virtio_backend_t
// value, and return the previous value.
cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_difference(
	_Atomic cap_rights_virtio_backend_t *b1, cap_rights_virtio_backend_t b2,
	memory_order order);

// Bitfield: cap_rights_virtio_iommu <uint32_t>
typedef struct cap_rights_virtio_iommu_b {
	// 0         bool bind_vpci
	// 1         bool manage_streams
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_virtio_iommu_t;

#define cap_rights_virtio_iommu_default()                                      \
	(cap_rights_virtio_iommu_t)                                            \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_virtio_iommu_cast(val_0)                                    \
	(cap_rights_virtio_iommu_t)                                            \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_virtio_iommu_raw(cap_rights_virtio_iommu_t bit_field);

void
cap_rights_virtio_iommu_init(cap_rights_virtio_iommu_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_clean(cap_rights_virtio_iommu_t bit_field);

bool
cap_rights_virtio_iommu_is_equal(cap_rights_virtio_iommu_t b1,
				 cap_rights_virtio_iommu_t b2);

bool
cap_rights_virtio_iommu_is_empty(cap_rights_virtio_iommu_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_virtio_iommu_is_clean(cap_rights_virtio_iommu_t bit_field);

// Union of boolean fields of two cap_rights_virtio_iommu_t values
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_union(cap_rights_virtio_iommu_t b1,
			      cap_rights_virtio_iommu_t b2);

// Intersection of boolean fields of two cap_rights_virtio_iommu_t values
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_intersection(cap_rights_virtio_iommu_t b1,
				     cap_rights_virtio_iommu_t b2);

// Invert all boolean fields in a cap_rights_virtio_iommu_t value
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_inverse(cap_rights_virtio_iommu_t b);

// Set difference of boolean fields of two cap_rights_virtio_iommu_t values
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_difference(cap_rights_virtio_iommu_t b1,
				   cap_rights_virtio_iommu_t b2);

// Atomically replace a cap_rights_virtio_iommu_t value with the union of its
// boolean fields with a given cap_rights_virtio_iommu_t value, and return the
// previous value.
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_union(_Atomic cap_rights_virtio_iommu_t *b1,
				     cap_rights_virtio_iommu_t		b2,
				     memory_order			order);

// Atomically replace a cap_rights_virtio_iommu_t value with the intersection of
// its boolean fields with a given cap_rights_virtio_iommu_t value, and return
// the previous value.
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_intersection(
	_Atomic cap_rights_virtio_iommu_t *b1, cap_rights_virtio_iommu_t b2,
	memory_order order);

// Atomically replace a cap_rights_virtio_iommu_t value with the set difference
// of its boolean fields and a given cap_rights_virtio_iommu_t value, and return
// the previous value.
cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_difference(_Atomic cap_rights_virtio_iommu_t *b1,
					  cap_rights_virtio_iommu_t	     b2,
					  memory_order order);

// Bitfield: cap_rights_vpci <uint32_t>
typedef struct cap_rights_vpci_b {
	// 0         bool attach
	// 1         bool bind
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vpci_t;

#define cap_rights_vpci_default()                                              \
	(cap_rights_vpci_t)                                                    \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vpci_cast(val_0)                                            \
	(cap_rights_vpci_t)                                                    \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vpci_raw(cap_rights_vpci_t bit_field);

void
cap_rights_vpci_init(cap_rights_vpci_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vpci_t
cap_rights_vpci_clean(cap_rights_vpci_t bit_field);

bool
cap_rights_vpci_is_equal(cap_rights_vpci_t b1, cap_rights_vpci_t b2);

bool
cap_rights_vpci_is_empty(cap_rights_vpci_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vpci_is_clean(cap_rights_vpci_t bit_field);

// Union of boolean fields of two cap_rights_vpci_t values
cap_rights_vpci_t
cap_rights_vpci_union(cap_rights_vpci_t b1, cap_rights_vpci_t b2);

// Intersection of boolean fields of two cap_rights_vpci_t values
cap_rights_vpci_t
cap_rights_vpci_intersection(cap_rights_vpci_t b1, cap_rights_vpci_t b2);

// Invert all boolean fields in a cap_rights_vpci_t value
cap_rights_vpci_t
cap_rights_vpci_inverse(cap_rights_vpci_t b);

// Set difference of boolean fields of two cap_rights_vpci_t values
cap_rights_vpci_t
cap_rights_vpci_difference(cap_rights_vpci_t b1, cap_rights_vpci_t b2);

// Atomically replace a cap_rights_vpci_t value with the union of its boolean
// fields with a given cap_rights_vpci_t value, and return the previous value.
cap_rights_vpci_t
cap_rights_vpci_atomic_union(_Atomic cap_rights_vpci_t *b1,
			     cap_rights_vpci_t b2, memory_order order);

// Atomically replace a cap_rights_vpci_t value with the intersection of its
// boolean fields with a given cap_rights_vpci_t value, and return the previous
// value.
cap_rights_vpci_t
cap_rights_vpci_atomic_intersection(_Atomic cap_rights_vpci_t *b1,
				    cap_rights_vpci_t b2, memory_order order);

// Atomically replace a cap_rights_vpci_t value with the set difference of its
// boolean fields and a given cap_rights_vpci_t value, and return the previous
// value.
cap_rights_vpci_t
cap_rights_vpci_atomic_difference(_Atomic cap_rights_vpci_t *b1,
				  cap_rights_vpci_t b2, memory_order order);

// Bitfield: cap_rights_vpm_group <uint32_t>
typedef struct cap_rights_vpm_group_b {
	// 0         bool attach_vcpu
	// 1         bool bind_virq
	// 2         bool query
	// 3         bool wakeup
	// 4         bool bind_power
	// 5         bool set_threshold
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vpm_group_t;

#define cap_rights_vpm_group_default()                                         \
	(cap_rights_vpm_group_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vpm_group_cast(val_0)                                       \
	(cap_rights_vpm_group_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vpm_group_raw(cap_rights_vpm_group_t bit_field);

void
cap_rights_vpm_group_init(cap_rights_vpm_group_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vpm_group_t
cap_rights_vpm_group_clean(cap_rights_vpm_group_t bit_field);

bool
cap_rights_vpm_group_is_equal(cap_rights_vpm_group_t b1,
			      cap_rights_vpm_group_t b2);

bool
cap_rights_vpm_group_is_empty(cap_rights_vpm_group_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vpm_group_is_clean(cap_rights_vpm_group_t bit_field);

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

// Bitfield: cap_rights_vrtc <uint32_t>
typedef struct cap_rights_vrtc_b {
	// 0         bool configure
	// 1         bool attach_addrspace
	// 2         bool set_time_base
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vrtc_t;

#define cap_rights_vrtc_default()                                              \
	(cap_rights_vrtc_t)                                                    \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vrtc_cast(val_0)                                            \
	(cap_rights_vrtc_t)                                                    \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vrtc_raw(cap_rights_vrtc_t bit_field);

void
cap_rights_vrtc_init(cap_rights_vrtc_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vrtc_t
cap_rights_vrtc_clean(cap_rights_vrtc_t bit_field);

bool
cap_rights_vrtc_is_equal(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2);

bool
cap_rights_vrtc_is_empty(cap_rights_vrtc_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vrtc_is_clean(cap_rights_vrtc_t bit_field);

// Union of boolean fields of two cap_rights_vrtc_t values
cap_rights_vrtc_t
cap_rights_vrtc_union(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2);

// Intersection of boolean fields of two cap_rights_vrtc_t values
cap_rights_vrtc_t
cap_rights_vrtc_intersection(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2);

// Invert all boolean fields in a cap_rights_vrtc_t value
cap_rights_vrtc_t
cap_rights_vrtc_inverse(cap_rights_vrtc_t b);

// Set difference of boolean fields of two cap_rights_vrtc_t values
cap_rights_vrtc_t
cap_rights_vrtc_difference(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2);

// Atomically replace a cap_rights_vrtc_t value with the union of its boolean
// fields with a given cap_rights_vrtc_t value, and return the previous value.
cap_rights_vrtc_t
cap_rights_vrtc_atomic_union(_Atomic cap_rights_vrtc_t *b1,
			     cap_rights_vrtc_t b2, memory_order order);

// Atomically replace a cap_rights_vrtc_t value with the intersection of its
// boolean fields with a given cap_rights_vrtc_t value, and return the previous
// value.
cap_rights_vrtc_t
cap_rights_vrtc_atomic_intersection(_Atomic cap_rights_vrtc_t *b1,
				    cap_rights_vrtc_t b2, memory_order order);

// Atomically replace a cap_rights_vrtc_t value with the set difference of its
// boolean fields and a given cap_rights_vrtc_t value, and return the previous
// value.
cap_rights_vrtc_t
cap_rights_vrtc_atomic_difference(_Atomic cap_rights_vrtc_t *b1,
				  cap_rights_vrtc_t b2, memory_order order);

// Bitfield: cap_rights_vsmmuv2 <uint32_t>
typedef struct cap_rights_vsmmuv2_b {
	// 0         bool manage_streams
	// 1         bool attach_addrspace
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_vsmmuv2_t;

#define cap_rights_vsmmuv2_default()                                           \
	(cap_rights_vsmmuv2_t)                                                 \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_vsmmuv2_cast(val_0)                                         \
	(cap_rights_vsmmuv2_t)                                                 \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_vsmmuv2_raw(cap_rights_vsmmuv2_t bit_field);

void
cap_rights_vsmmuv2_init(cap_rights_vsmmuv2_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_clean(cap_rights_vsmmuv2_t bit_field);

bool
cap_rights_vsmmuv2_is_equal(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2);

bool
cap_rights_vsmmuv2_is_empty(cap_rights_vsmmuv2_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_vsmmuv2_is_clean(cap_rights_vsmmuv2_t bit_field);

// Union of boolean fields of two cap_rights_vsmmuv2_t values
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_union(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2);

// Intersection of boolean fields of two cap_rights_vsmmuv2_t values
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_intersection(cap_rights_vsmmuv2_t b1,
				cap_rights_vsmmuv2_t b2);

// Invert all boolean fields in a cap_rights_vsmmuv2_t value
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_inverse(cap_rights_vsmmuv2_t b);

// Set difference of boolean fields of two cap_rights_vsmmuv2_t values
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_difference(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2);

// Atomically replace a cap_rights_vsmmuv2_t value with the union of its boolean
// fields with a given cap_rights_vsmmuv2_t value, and return the previous
// value.
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_union(_Atomic cap_rights_vsmmuv2_t *b1,
				cap_rights_vsmmuv2_t b2, memory_order order);

// Atomically replace a cap_rights_vsmmuv2_t value with the intersection of its
// boolean fields with a given cap_rights_vsmmuv2_t value, and return the
// previous value.
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_intersection(_Atomic cap_rights_vsmmuv2_t *b1,
				       cap_rights_vsmmuv2_t	     b2,
				       memory_order		     order);

// Atomically replace a cap_rights_vsmmuv2_t value with the set difference of
// its boolean fields and a given cap_rights_vsmmuv2_t value, and return the
// previous value.
cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_difference(_Atomic cap_rights_vsmmuv2_t *b1,
				     cap_rights_vsmmuv2_t	   b2,
				     memory_order		   order);

// Bitfield: cap_rights_watchdog <uint32_t>
typedef struct cap_rights_watchdog_b {
	// 0         bool attach_vcpu
	// 1         bool bind_virq
	// 2         bool manage
	// 31        bool object_activate
	uint32_t bf[1];
} cap_rights_watchdog_t;

#define cap_rights_watchdog_default()                                          \
	(cap_rights_watchdog_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define cap_rights_watchdog_cast(val_0)                                        \
	(cap_rights_watchdog_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
cap_rights_watchdog_raw(cap_rights_watchdog_t bit_field);

void
cap_rights_watchdog_init(cap_rights_watchdog_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
cap_rights_watchdog_t
cap_rights_watchdog_clean(cap_rights_watchdog_t bit_field);

bool
cap_rights_watchdog_is_equal(cap_rights_watchdog_t b1,
			     cap_rights_watchdog_t b2);

bool
cap_rights_watchdog_is_empty(cap_rights_watchdog_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
cap_rights_watchdog_is_clean(cap_rights_watchdog_t bit_field);

// Union of boolean fields of two cap_rights_watchdog_t values
cap_rights_watchdog_t
cap_rights_watchdog_union(cap_rights_watchdog_t b1, cap_rights_watchdog_t b2);

// Intersection of boolean fields of two cap_rights_watchdog_t values
cap_rights_watchdog_t
cap_rights_watchdog_intersection(cap_rights_watchdog_t b1,
				 cap_rights_watchdog_t b2);

// Invert all boolean fields in a cap_rights_watchdog_t value
cap_rights_watchdog_t
cap_rights_watchdog_inverse(cap_rights_watchdog_t b);

// Set difference of boolean fields of two cap_rights_watchdog_t values
cap_rights_watchdog_t
cap_rights_watchdog_difference(cap_rights_watchdog_t b1,
			       cap_rights_watchdog_t b2);

// Atomically replace a cap_rights_watchdog_t value with the union of its
// boolean fields with a given cap_rights_watchdog_t value, and return the
// previous value.
cap_rights_watchdog_t
cap_rights_watchdog_atomic_union(_Atomic cap_rights_watchdog_t *b1,
				 cap_rights_watchdog_t b2, memory_order order);

// Atomically replace a cap_rights_watchdog_t value with the intersection of its
// boolean fields with a given cap_rights_watchdog_t value, and return the
// previous value.
cap_rights_watchdog_t
cap_rights_watchdog_atomic_intersection(_Atomic cap_rights_watchdog_t *b1,
					cap_rights_watchdog_t	       b2,
					memory_order		       order);

// Atomically replace a cap_rights_watchdog_t value with the set difference of
// its boolean fields and a given cap_rights_watchdog_t value, and return the
// previous value.
cap_rights_watchdog_t
cap_rights_watchdog_atomic_difference(_Atomic cap_rights_watchdog_t *b1,
				      cap_rights_watchdog_t	     b2,
				      memory_order		     order);

typedef enum error_e {
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
	ERROR_ADDR_OVERLAP		  = 23,
	ERROR_ADDR_NOTFOUND		  = 24,
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
	ERROR_MEMEXTENT_TYPE		  = 121,
	ERROR_EXISTING_MAPPING		  = 200
} error_t;

#define ERROR__MAX ERROR_EXISTING_MAPPING
#define ERROR__MIN ERROR_RETRY

typedef enum scheduler_variant_e {
	SCHEDULER_VARIANT_TRIVIAL = 0,
	SCHEDULER_VARIANT_FPRR	  = 1
} scheduler_variant_t;

#define SCHEDULER_VARIANT__MAX SCHEDULER_VARIANT_FPRR
#define SCHEDULER_VARIANT__MIN SCHEDULER_VARIANT_TRIVIAL

// Bitfield: hyp_api_flags0 <uint64_t>
typedef struct hyp_api_flags0_b {
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
	// 11        const bool vcpu_run
	// 12        const bool trace_profile
	// 13        const bool vpci
	// 14        const bool power
	// 63:32,27:17,15 const uint64_t res0_0
	// 16        const bool reserved_16
	// 31:28     const scheduler_variant_t scheduler
	uint64_t bf[1];
} hyp_api_flags0_t;

#define hyp_api_flags0_default()                                               \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = { 0x10006fffU }                                          \
	}

#define hyp_api_flags0_cast(val_0)                                             \
	(hyp_api_flags0_t)                                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
hyp_api_flags0_raw(hyp_api_flags0_t bit_field);

void
hyp_api_flags0_init(hyp_api_flags0_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
hyp_api_flags0_t
hyp_api_flags0_clean(hyp_api_flags0_t bit_field);

bool
hyp_api_flags0_is_equal(hyp_api_flags0_t b1, hyp_api_flags0_t b2);

bool
hyp_api_flags0_is_empty(hyp_api_flags0_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
hyp_api_flags0_is_clean(hyp_api_flags0_t bit_field);

// Bitfield: hyp_api_flags1 <uint64_t>
typedef struct hyp_api_flags1_b {
	// 0         const bool arm_v82_sve
	// 1         const bool vgic_ext_spis
	// 2         const bool vgic_ext_ppis
	uint64_t bf[1];
} hyp_api_flags1_t;

#define hyp_api_flags1_default()                                               \
	(hyp_api_flags1_t)                                                     \
	{                                                                      \
		.bf = { 0x2U }                                                 \
	}

#define hyp_api_flags1_cast(val_0)                                             \
	(hyp_api_flags1_t)                                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
hyp_api_flags1_raw(hyp_api_flags1_t bit_field);

void
hyp_api_flags1_init(hyp_api_flags1_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
hyp_api_flags1_t
hyp_api_flags1_clean(hyp_api_flags1_t bit_field);

bool
hyp_api_flags1_is_equal(hyp_api_flags1_t b1, hyp_api_flags1_t b2);

bool
hyp_api_flags1_is_empty(hyp_api_flags1_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
hyp_api_flags1_is_clean(hyp_api_flags1_t bit_field);

// Union of boolean fields of two hyp_api_flags1_t values
hyp_api_flags1_t
hyp_api_flags1_union(hyp_api_flags1_t b1, hyp_api_flags1_t b2);

// Intersection of boolean fields of two hyp_api_flags1_t values
hyp_api_flags1_t
hyp_api_flags1_intersection(hyp_api_flags1_t b1, hyp_api_flags1_t b2);

// Invert all boolean fields in a hyp_api_flags1_t value
hyp_api_flags1_t
hyp_api_flags1_inverse(hyp_api_flags1_t b);

// Set difference of boolean fields of two hyp_api_flags1_t values
hyp_api_flags1_t
hyp_api_flags1_difference(hyp_api_flags1_t b1, hyp_api_flags1_t b2);

// Atomically replace a hyp_api_flags1_t value with the union of its boolean
// fields with a given hyp_api_flags1_t value, and return the previous value.
hyp_api_flags1_t
hyp_api_flags1_atomic_union(_Atomic hyp_api_flags1_t *b1, hyp_api_flags1_t b2,
			    memory_order order);

// Atomically replace a hyp_api_flags1_t value with the intersection of its
// boolean fields with a given hyp_api_flags1_t value, and return the previous
// value.
hyp_api_flags1_t
hyp_api_flags1_atomic_intersection(_Atomic hyp_api_flags1_t *b1,
				   hyp_api_flags1_t b2, memory_order order);

// Atomically replace a hyp_api_flags1_t value with the set difference of its
// boolean fields and a given hyp_api_flags1_t value, and return the previous
// value.
hyp_api_flags1_t
hyp_api_flags1_atomic_difference(_Atomic hyp_api_flags1_t *b1,
				 hyp_api_flags1_t b2, memory_order order);

// Bitfield: hyp_api_flags2 <uint64_t>
typedef struct hyp_api_flags2_b {
	// 63:0      const uint64_t res0_0
	uint64_t bf[1];
} hyp_api_flags2_t;

#define hyp_api_flags2_default()                                               \
	(hyp_api_flags2_t)                                                     \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define hyp_api_flags2_cast(val_0)                                             \
	(hyp_api_flags2_t)                                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
hyp_api_flags2_raw(hyp_api_flags2_t bit_field);

void
hyp_api_flags2_init(hyp_api_flags2_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
hyp_api_flags2_t
hyp_api_flags2_clean(hyp_api_flags2_t bit_field);

bool
hyp_api_flags2_is_equal(hyp_api_flags2_t b1, hyp_api_flags2_t b2);

bool
hyp_api_flags2_is_empty(hyp_api_flags2_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
hyp_api_flags2_is_clean(hyp_api_flags2_t bit_field);

typedef enum hyp_variant_e {
	HYP_VARIANT_UNKNOWN  = 0,
	HYP_VARIANT_GUNYAH   = 72,
	HYP_VARIANT_QUALCOMM = 81
} hyp_variant_t;

#define HYP_VARIANT__MAX HYP_VARIANT_QUALCOMM
#define HYP_VARIANT__MIN HYP_VARIANT_UNKNOWN

// Bitfield: hyp_api_info <uint64_t>
typedef struct hyp_api_info_b {
	// 13:0      const uint16_t api_version
	// 14        const bool big_endian
	// 15        const bool is_64bit
	// 63:56     const hyp_variant_t variant
	uint64_t bf[1];
} hyp_api_info_t;

#define hyp_api_info_default()                                                 \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = { 0x5100000000008001U }                                  \
	}

#define hyp_api_info_cast(val_0)                                               \
	(hyp_api_info_t)                                                       \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
hyp_api_info_raw(hyp_api_info_t bit_field);

void
hyp_api_info_init(hyp_api_info_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
hyp_api_info_t
hyp_api_info_clean(hyp_api_info_t bit_field);

bool
hyp_api_info_is_equal(hyp_api_info_t b1, hyp_api_info_t b2);

bool
hyp_api_info_is_empty(hyp_api_info_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
hyp_api_info_is_clean(hyp_api_info_t bit_field);

typedef enum pgtable_access_e {
	PGTABLE_ACCESS_NONE = 0,
	PGTABLE_ACCESS_X    = 1,
	PGTABLE_ACCESS_W    = 2,
	PGTABLE_ACCESS_R    = 4,
	PGTABLE_ACCESS_RX   = 5,
	PGTABLE_ACCESS_RW   = 6,
	PGTABLE_ACCESS_RWX  = 7
} pgtable_access_t;

#define PGTABLE_ACCESS__MAX PGTABLE_ACCESS_RWX
#define PGTABLE_ACCESS__MIN PGTABLE_ACCESS_NONE

// Bitfield: memextent_access_attrs <uint32_t>
typedef struct memextent_access_attrs_b {
	// 2:0       pgtable_access_t user_access
	// 31:7,3    const uint64_t res_0
	// 6:4       pgtable_access_t kernel_access
	uint32_t bf[1];
} memextent_access_attrs_t;

#define memextent_access_attrs_default()                                       \
	(memextent_access_attrs_t)                                             \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define memextent_access_attrs_cast(val_0)                                     \
	(memextent_access_attrs_t)                                             \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
memextent_access_attrs_raw(memextent_access_attrs_t bit_field);

void
memextent_access_attrs_init(memextent_access_attrs_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
memextent_access_attrs_t
memextent_access_attrs_clean(memextent_access_attrs_t bit_field);

bool
memextent_access_attrs_is_equal(memextent_access_attrs_t b1,
				memextent_access_attrs_t b2);

bool
memextent_access_attrs_is_empty(memextent_access_attrs_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
memextent_access_attrs_is_clean(memextent_access_attrs_t bit_field);

typedef enum memextent_memtype_e {
	MEMEXTENT_MEMTYPE_ANY	   = 0,
	MEMEXTENT_MEMTYPE_DEVICE   = 1,
	MEMEXTENT_MEMTYPE_UNCACHED = 2,
	MEMEXTENT_MEMTYPE_CACHED   = 3
} memextent_memtype_t;

#define MEMEXTENT_MEMTYPE__MAX MEMEXTENT_MEMTYPE_CACHED
#define MEMEXTENT_MEMTYPE__MIN MEMEXTENT_MEMTYPE_ANY

typedef enum memextent_type_e {
	MEMEXTENT_TYPE_BASIC  = 0,
	MEMEXTENT_TYPE_SPARSE = 1
} memextent_type_t;

#define MEMEXTENT_TYPE__MAX MEMEXTENT_TYPE_SPARSE
#define MEMEXTENT_TYPE__MIN MEMEXTENT_TYPE_BASIC

// Bitfield: memextent_attrs <uint32_t>
typedef struct memextent_attrs_b {
	// 2:0       pgtable_access_t access
	// 31:18,15:10,7:3 const uint64_t res_0
	// 9:8       memextent_memtype_t memtype
	// 17:16     memextent_type_t type
	uint32_t bf[1];
} memextent_attrs_t;

#define memextent_attrs_default()                                              \
	(memextent_attrs_t)                                                    \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define memextent_attrs_cast(val_0)                                            \
	(memextent_attrs_t)                                                    \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
memextent_attrs_raw(memextent_attrs_t bit_field);

void
memextent_attrs_init(memextent_attrs_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
memextent_attrs_t
memextent_attrs_clean(memextent_attrs_t bit_field);

bool
memextent_attrs_is_equal(memextent_attrs_t b1, memextent_attrs_t b2);

bool
memextent_attrs_is_empty(memextent_attrs_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
memextent_attrs_is_clean(memextent_attrs_t bit_field);

typedef enum memextent_donate_type_e {
	MEMEXTENT_DONATE_TYPE_TO_CHILD	     = 0,
	MEMEXTENT_DONATE_TYPE_TO_PARENT	     = 1,
	MEMEXTENT_DONATE_TYPE_TO_SIBLING     = 2,
	MEMEXTENT_DONATE_TYPE_TO_PROTECTED   = 3,
	MEMEXTENT_DONATE_TYPE_FROM_PROTECTED = 4
} memextent_donate_type_t;

#define MEMEXTENT_DONATE_TYPE__MAX MEMEXTENT_DONATE_TYPE_FROM_PROTECTED
#define MEMEXTENT_DONATE_TYPE__MIN MEMEXTENT_DONATE_TYPE_TO_CHILD

// Bitfield: memextent_donate_options <uint32_t>
typedef struct memextent_donate_options_b {
	// 7:0       memextent_donate_type_t type
	// 30:8      const uint64_t res_0
	// 31        bool no_sync
	uint32_t bf[1];
} memextent_donate_options_t;

#define memextent_donate_options_default()                                     \
	(memextent_donate_options_t)                                           \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define memextent_donate_options_cast(val_0)                                   \
	(memextent_donate_options_t)                                           \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
memextent_donate_options_raw(memextent_donate_options_t bit_field);

void
memextent_donate_options_init(memextent_donate_options_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
memextent_donate_options_t
memextent_donate_options_clean(memextent_donate_options_t bit_field);

bool
memextent_donate_options_is_equal(memextent_donate_options_t b1,
				  memextent_donate_options_t b2);

bool
memextent_donate_options_is_empty(memextent_donate_options_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
memextent_donate_options_is_clean(memextent_donate_options_t bit_field);

typedef enum pgtable_vm_memtype_e {
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

#define PGTABLE_VM_MEMTYPE__MAX PGTABLE_VM_MEMTYPE_NORMAL_WB
#define PGTABLE_VM_MEMTYPE__MIN PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE

// Bitfield: memextent_mapping_attrs <uint32_t>
typedef struct memextent_mapping_attrs_b {
	// 2:0       pgtable_access_t user_access
	// 31:24,15:7,3 const uint64_t res_0
	// 6:4       pgtable_access_t kernel_access
	// 23:16     pgtable_vm_memtype_t memtype
	uint32_t bf[1];
} memextent_mapping_attrs_t;

#define memextent_mapping_attrs_default()                                      \
	(memextent_mapping_attrs_t)                                            \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define memextent_mapping_attrs_cast(val_0)                                    \
	(memextent_mapping_attrs_t)                                            \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
memextent_mapping_attrs_raw(memextent_mapping_attrs_t bit_field);

void
memextent_mapping_attrs_init(memextent_mapping_attrs_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
memextent_mapping_attrs_t
memextent_mapping_attrs_clean(memextent_mapping_attrs_t bit_field);

bool
memextent_mapping_attrs_is_equal(memextent_mapping_attrs_t b1,
				 memextent_mapping_attrs_t b2);

bool
memextent_mapping_attrs_is_empty(memextent_mapping_attrs_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
memextent_mapping_attrs_is_clean(memextent_mapping_attrs_t bit_field);

typedef enum memextent_modify_op_e {
	MEMEXTENT_MODIFY_OP_UNMAP_ALL	      = 0,
	MEMEXTENT_MODIFY_OP_ZERO_RANGE	      = 1,
	MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE = 2,
	MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE = 3,
	MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET = 4,
	MEMEXTENT_MODIFY_OP_SYNC_ALL	      = 255
} memextent_modify_op_t;

#define MEMEXTENT_MODIFY_OP__MAX MEMEXTENT_MODIFY_OP_SYNC_ALL
#define MEMEXTENT_MODIFY_OP__MIN MEMEXTENT_MODIFY_OP_UNMAP_ALL

// Bitfield: memextent_modify_flags <uint32_t>
typedef struct memextent_modify_flags_b {
	// 7:0       memextent_modify_op_t op
	// 30:8      const uint64_t res_0
	// 31        bool no_sync
	uint32_t bf[1];
} memextent_modify_flags_t;

#define memextent_modify_flags_default()                                       \
	(memextent_modify_flags_t)                                             \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define memextent_modify_flags_cast(val_0)                                     \
	(memextent_modify_flags_t)                                             \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
memextent_modify_flags_raw(memextent_modify_flags_t bit_field);

void
memextent_modify_flags_init(memextent_modify_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
memextent_modify_flags_t
memextent_modify_flags_clean(memextent_modify_flags_t bit_field);

bool
memextent_modify_flags_is_equal(memextent_modify_flags_t b1,
				memextent_modify_flags_t b2);

bool
memextent_modify_flags_is_empty(memextent_modify_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
memextent_modify_flags_is_clean(memextent_modify_flags_t bit_field);

typedef uint64_t microseconds_t;
typedef uint64_t milliseconds_t;

// Bitfield: msgqueue_create_info <uint64_t>
typedef struct msgqueue_create_info_b {
	// 15:0      uint16_t queue_depth
	// 31:16     uint16_t max_msg_size
	uint64_t bf[1];
} msgqueue_create_info_t;

#define msgqueue_create_info_default()                                         \
	(msgqueue_create_info_t)                                               \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define msgqueue_create_info_cast(val_0)                                       \
	(msgqueue_create_info_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
msgqueue_create_info_raw(msgqueue_create_info_t bit_field);

void
msgqueue_create_info_init(msgqueue_create_info_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
msgqueue_create_info_t
msgqueue_create_info_clean(msgqueue_create_info_t bit_field);

bool
msgqueue_create_info_is_equal(msgqueue_create_info_t b1,
			      msgqueue_create_info_t b2);

bool
msgqueue_create_info_is_empty(msgqueue_create_info_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
msgqueue_create_info_is_clean(msgqueue_create_info_t bit_field);

// Bitfield: msgqueue_send_flags <uint32_t>
typedef struct msgqueue_send_flags_b {
	// 0         bool push
	uint32_t bf[1];
} msgqueue_send_flags_t;

#define msgqueue_send_flags_default()                                          \
	(msgqueue_send_flags_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define msgqueue_send_flags_cast(val_0)                                        \
	(msgqueue_send_flags_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
msgqueue_send_flags_raw(msgqueue_send_flags_t bit_field);

void
msgqueue_send_flags_init(msgqueue_send_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
msgqueue_send_flags_t
msgqueue_send_flags_clean(msgqueue_send_flags_t bit_field);

bool
msgqueue_send_flags_is_equal(msgqueue_send_flags_t b1,
			     msgqueue_send_flags_t b2);

bool
msgqueue_send_flags_is_empty(msgqueue_send_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
msgqueue_send_flags_is_clean(msgqueue_send_flags_t bit_field);

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

typedef enum partition_donate_type_e {
	PARTITION_DONATE_TYPE_TO_PARTITION = 0,
	PARTITION_DONATE_TYPE_ADD_HEAP	   = 1,
	PARTITION_DONATE_TYPE_REMOVE_HEAP  = 2
} partition_donate_type_t;

#define PARTITION_DONATE_TYPE__MAX PARTITION_DONATE_TYPE_REMOVE_HEAP
#define PARTITION_DONATE_TYPE__MIN PARTITION_DONATE_TYPE_TO_PARTITION

// Bitfield: partition_donate_flags <uint32_t>
typedef struct partition_donate_flags_b {
	// 7:0       partition_donate_type_t type
	// 31:8      const uint32_t res0
	uint32_t bf[1];
} partition_donate_flags_t;

#define partition_donate_flags_default()                                       \
	(partition_donate_flags_t)                                             \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define partition_donate_flags_cast(val_0)                                     \
	(partition_donate_flags_t)                                             \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
partition_donate_flags_raw(partition_donate_flags_t bit_field);

void
partition_donate_flags_init(partition_donate_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
partition_donate_flags_t
partition_donate_flags_clean(partition_donate_flags_t bit_field);

bool
partition_donate_flags_is_equal(partition_donate_flags_t b1,
				partition_donate_flags_t b2);

bool
partition_donate_flags_is_empty(partition_donate_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
partition_donate_flags_is_clean(partition_donate_flags_t bit_field);

typedef enum partition_query_type_e {
	PARTITION_QUERY_TYPE_HEAP_IS_FREE = 0,
	PARTITION_QUERY_TYPE_HEAP_STATS	  = 1
} partition_query_type_t;

#define PARTITION_QUERY_TYPE__MAX PARTITION_QUERY_TYPE_HEAP_STATS
#define PARTITION_QUERY_TYPE__MIN PARTITION_QUERY_TYPE_HEAP_IS_FREE

// Bitfield: partition_query_flags <uint32_t>
typedef struct partition_query_flags_b {
	// 7:0       partition_query_type_t type
	// 31:8      const uint32_t res0
	uint32_t bf[1];
} partition_query_flags_t;

#define partition_query_flags_default()                                        \
	(partition_query_flags_t)                                              \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define partition_query_flags_cast(val_0)                                      \
	(partition_query_flags_t)                                              \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
partition_query_flags_raw(partition_query_flags_t bit_field);

void
partition_query_flags_init(partition_query_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
partition_query_flags_t
partition_query_flags_clean(partition_query_flags_t bit_field);

bool
partition_query_flags_is_equal(partition_query_flags_t b1,
			       partition_query_flags_t b2);

bool
partition_query_flags_is_empty(partition_query_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
partition_query_flags_is_clean(partition_query_flags_t bit_field);

// Bitfield: pci_capability_access_flags <uint64_t>
typedef struct pci_capability_access_flags_b {
	// 0         bool passthrough_visible
	// 1         bool passthrough_writable
	// 2         bool lockdown_visible
	// 3         bool lockdown_writable
	uint64_t bf[1];
} pci_capability_access_flags_t;

#define pci_capability_access_flags_default()                                  \
	(pci_capability_access_flags_t)                                        \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define pci_capability_access_flags_cast(val_0)                                \
	(pci_capability_access_flags_t)                                        \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
pci_capability_access_flags_raw(pci_capability_access_flags_t bit_field);

void
pci_capability_access_flags_init(pci_capability_access_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
pci_capability_access_flags_t
pci_capability_access_flags_clean(pci_capability_access_flags_t bit_field);

bool
pci_capability_access_flags_is_equal(pci_capability_access_flags_t b1,
				     pci_capability_access_flags_t b2);

bool
pci_capability_access_flags_is_empty(pci_capability_access_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
pci_capability_access_flags_is_clean(pci_capability_access_flags_t bit_field);

// Union of boolean fields of two pci_capability_access_flags_t values
pci_capability_access_flags_t
pci_capability_access_flags_union(pci_capability_access_flags_t b1,
				  pci_capability_access_flags_t b2);

// Intersection of boolean fields of two pci_capability_access_flags_t values
pci_capability_access_flags_t
pci_capability_access_flags_intersection(pci_capability_access_flags_t b1,
					 pci_capability_access_flags_t b2);

// Invert all boolean fields in a pci_capability_access_flags_t value
pci_capability_access_flags_t
pci_capability_access_flags_inverse(pci_capability_access_flags_t b);

// Set difference of boolean fields of two pci_capability_access_flags_t values
pci_capability_access_flags_t
pci_capability_access_flags_difference(pci_capability_access_flags_t b1,
				       pci_capability_access_flags_t b2);

// Atomically replace a pci_capability_access_flags_t value with the union of
// its boolean fields with a given pci_capability_access_flags_t value, and
// return the previous value.
pci_capability_access_flags_t
pci_capability_access_flags_atomic_union(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order);

// Atomically replace a pci_capability_access_flags_t value with the
// intersection of its boolean fields with a given pci_capability_access_flags_t
// value, and return the previous value.
pci_capability_access_flags_t
pci_capability_access_flags_atomic_intersection(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order);

// Atomically replace a pci_capability_access_flags_t value with the set
// difference of its boolean fields and a given pci_capability_access_flags_t
// value, and return the previous value.
pci_capability_access_flags_t
pci_capability_access_flags_atomic_difference(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order);

// Bitfield: pci_function_option_flags <uint64_t>
typedef struct pci_function_option_flags_b {
	// 0         bool passthrough
	// 1         bool sr_iov_vf
	uint64_t bf[1];
} pci_function_option_flags_t;

#define pci_function_option_flags_default()                                    \
	(pci_function_option_flags_t)                                          \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define pci_function_option_flags_cast(val_0)                                  \
	(pci_function_option_flags_t)                                          \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
pci_function_option_flags_raw(pci_function_option_flags_t bit_field);

void
pci_function_option_flags_init(pci_function_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
pci_function_option_flags_t
pci_function_option_flags_clean(pci_function_option_flags_t bit_field);

bool
pci_function_option_flags_is_equal(pci_function_option_flags_t b1,
				   pci_function_option_flags_t b2);

bool
pci_function_option_flags_is_empty(pci_function_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
pci_function_option_flags_is_clean(pci_function_option_flags_t bit_field);

// Union of boolean fields of two pci_function_option_flags_t values
pci_function_option_flags_t
pci_function_option_flags_union(pci_function_option_flags_t b1,
				pci_function_option_flags_t b2);

// Intersection of boolean fields of two pci_function_option_flags_t values
pci_function_option_flags_t
pci_function_option_flags_intersection(pci_function_option_flags_t b1,
				       pci_function_option_flags_t b2);

// Invert all boolean fields in a pci_function_option_flags_t value
pci_function_option_flags_t
pci_function_option_flags_inverse(pci_function_option_flags_t b);

// Set difference of boolean fields of two pci_function_option_flags_t values
pci_function_option_flags_t
pci_function_option_flags_difference(pci_function_option_flags_t b1,
				     pci_function_option_flags_t b2);

// Atomically replace a pci_function_option_flags_t value with the union of its
// boolean fields with a given pci_function_option_flags_t value, and return the
// previous value.
pci_function_option_flags_t
pci_function_option_flags_atomic_union(_Atomic pci_function_option_flags_t *b1,
				       pci_function_option_flags_t	    b2,
				       memory_order order);

// Atomically replace a pci_function_option_flags_t value with the intersection
// of its boolean fields with a given pci_function_option_flags_t value, and
// return the previous value.
pci_function_option_flags_t
pci_function_option_flags_atomic_intersection(
	_Atomic pci_function_option_flags_t *b1, pci_function_option_flags_t b2,
	memory_order order);

// Atomically replace a pci_function_option_flags_t value with the set
// difference of its boolean fields and a given pci_function_option_flags_t
// value, and return the previous value.
pci_function_option_flags_t
pci_function_option_flags_atomic_difference(
	_Atomic pci_function_option_flags_t *b1, pci_function_option_flags_t b2,
	memory_order order);

typedef enum pci_host_lockdown_state_e {
	PCI_HOST_LOCKDOWN_STATE_PERMISSIVE = 0,
	PCI_HOST_LOCKDOWN_STATE_SCANNING   = 1,
	PCI_HOST_LOCKDOWN_STATE_RESTRICTED = 2
} pci_host_lockdown_state_t;

#define PCI_HOST_LOCKDOWN_STATE__MAX PCI_HOST_LOCKDOWN_STATE_RESTRICTED
#define PCI_HOST_LOCKDOWN_STATE__MIN PCI_HOST_LOCKDOWN_STATE_PERMISSIVE

// Bitfield: pci_host_option_flags <uint64_t>
typedef struct pci_host_option_flags_b {
	// 0         bool pcie
	// 1         bool lockdown
	uint64_t bf[1];
} pci_host_option_flags_t;

#define pci_host_option_flags_default()                                        \
	(pci_host_option_flags_t)                                              \
	{                                                                      \
		.bf = { 0x1U }                                                 \
	}

#define pci_host_option_flags_cast(val_0)                                      \
	(pci_host_option_flags_t)                                              \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
pci_host_option_flags_raw(pci_host_option_flags_t bit_field);

void
pci_host_option_flags_init(pci_host_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
pci_host_option_flags_t
pci_host_option_flags_clean(pci_host_option_flags_t bit_field);

bool
pci_host_option_flags_is_equal(pci_host_option_flags_t b1,
			       pci_host_option_flags_t b2);

bool
pci_host_option_flags_is_empty(pci_host_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
pci_host_option_flags_is_clean(pci_host_option_flags_t bit_field);

// Union of boolean fields of two pci_host_option_flags_t values
pci_host_option_flags_t
pci_host_option_flags_union(pci_host_option_flags_t b1,
			    pci_host_option_flags_t b2);

// Intersection of boolean fields of two pci_host_option_flags_t values
pci_host_option_flags_t
pci_host_option_flags_intersection(pci_host_option_flags_t b1,
				   pci_host_option_flags_t b2);

// Invert all boolean fields in a pci_host_option_flags_t value
pci_host_option_flags_t
pci_host_option_flags_inverse(pci_host_option_flags_t b);

// Set difference of boolean fields of two pci_host_option_flags_t values
pci_host_option_flags_t
pci_host_option_flags_difference(pci_host_option_flags_t b1,
				 pci_host_option_flags_t b2);

// Atomically replace a pci_host_option_flags_t value with the union of its
// boolean fields with a given pci_host_option_flags_t value, and return the
// previous value.
pci_host_option_flags_t
pci_host_option_flags_atomic_union(_Atomic pci_host_option_flags_t *b1,
				   pci_host_option_flags_t	    b2,
				   memory_order			    order);

// Atomically replace a pci_host_option_flags_t value with the intersection of
// its boolean fields with a given pci_host_option_flags_t value, and return the
// previous value.
pci_host_option_flags_t
pci_host_option_flags_atomic_intersection(_Atomic pci_host_option_flags_t *b1,
					  pci_host_option_flags_t	   b2,
					  memory_order order);

// Atomically replace a pci_host_option_flags_t value with the set difference of
// its boolean fields and a given pci_host_option_flags_t value, and return the
// previous value.
pci_host_option_flags_t
pci_host_option_flags_atomic_difference(_Atomic pci_host_option_flags_t *b1,
					pci_host_option_flags_t		 b2,
					memory_order			 order);

// Bitfield: pci_responder_id <uint16_t>
typedef struct pci_responder_id_b {
	// 2:0       index_t function
	// 7:3       index_t slot
	// 15:8      index_t bus
	uint16_t bf[1];
} pci_responder_id_t;

#define pci_responder_id_default()                                             \
	(pci_responder_id_t)                                                   \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define pci_responder_id_cast(val_0)                                           \
	(pci_responder_id_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint16_t
pci_responder_id_raw(pci_responder_id_t bit_field);

void
pci_responder_id_init(pci_responder_id_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
pci_responder_id_t
pci_responder_id_clean(pci_responder_id_t bit_field);

bool
pci_responder_id_is_equal(pci_responder_id_t b1, pci_responder_id_t b2);

bool
pci_responder_id_is_empty(pci_responder_id_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
pci_responder_id_is_clean(pci_responder_id_t bit_field);

typedef uint64_t register_t;

struct rm_env_data_hdr_s {
	uint32_t signature;
	uint16_t version;
	uint8_t	 pad_to_data_payload_offset_[2];
	uint32_t data_payload_offset;
	uint32_t data_payload_size;
};

// Bitfield: root_env_mmio_range_properties <uint64_t>
typedef struct root_env_mmio_range_properties_b {
	// 31:0      uint32_t num_pages
	// 34:32     pgtable_access_t access
	// 47:40     uint8_t res_s2pt_attr
	// 62        bool pvm_unmapped
	// 63        bool non_exclusive
	uint64_t bf[1];
} root_env_mmio_range_properties_t;

#define root_env_mmio_range_properties_default()                               \
	(root_env_mmio_range_properties_t)                                     \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define root_env_mmio_range_properties_cast(val_0)                             \
	(root_env_mmio_range_properties_t)                                     \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
root_env_mmio_range_properties_raw(root_env_mmio_range_properties_t bit_field);

void
root_env_mmio_range_properties_init(root_env_mmio_range_properties_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
root_env_mmio_range_properties_t
root_env_mmio_range_properties_clean(root_env_mmio_range_properties_t bit_field);

bool
root_env_mmio_range_properties_is_equal(root_env_mmio_range_properties_t b1,
					root_env_mmio_range_properties_t b2);

bool
root_env_mmio_range_properties_is_empty(
	root_env_mmio_range_properties_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
root_env_mmio_range_properties_is_clean(
	root_env_mmio_range_properties_t bit_field);

struct root_env_mmio_range_descriptor_s {
	paddr_t				 address;
	root_env_mmio_range_properties_t attrs;
};

typedef uint64_t vmaddr_t;

struct rt_env_data_s {
	uint32_t signature;
	uint16_t version;
	uint8_t	 pad_to_runtime_ipa_[2];
	vmaddr_t runtime_ipa;
	vmaddr_t app_ipa;
	vmaddr_t app_heap_ipa;
	size_t	 app_heap_size;
	cap_id_t vcpu_capid;
	uint64_t timer_freq;
	paddr_t	 gicd_base;
	paddr_t	 gicr_base;
	size_t	 rm_config_offset;
	size_t	 rm_config_size;
};

typedef enum scheduler_yield_hint_e {
	SCHEDULER_YIELD_HINT_YIELD	     = 0,
	SCHEDULER_YIELD_HINT_YIELD_TO_THREAD = 1,
	SCHEDULER_YIELD_HINT_YIELD_LOWER     = 2
} scheduler_yield_hint_t;

#define SCHEDULER_YIELD_HINT__MAX SCHEDULER_YIELD_HINT_YIELD_LOWER
#define SCHEDULER_YIELD_HINT__MIN SCHEDULER_YIELD_HINT_YIELD

// Bitfield: scheduler_yield_control <uint32_t>
typedef struct scheduler_yield_control_b {
	// 15:0      scheduler_yield_hint_t hint
	// 31        bool impl_def
	uint32_t bf[1];
} scheduler_yield_control_t;

#define scheduler_yield_control_default()                                      \
	(scheduler_yield_control_t)                                            \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define scheduler_yield_control_cast(val_0)                                    \
	(scheduler_yield_control_t)                                            \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
scheduler_yield_control_raw(scheduler_yield_control_t bit_field);

void
scheduler_yield_control_init(scheduler_yield_control_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
scheduler_yield_control_t
scheduler_yield_control_clean(scheduler_yield_control_t bit_field);

bool
scheduler_yield_control_is_equal(scheduler_yield_control_t b1,
				 scheduler_yield_control_t b2);

bool
scheduler_yield_control_is_empty(scheduler_yield_control_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
scheduler_yield_control_is_clean(scheduler_yield_control_t bit_field);

typedef enum sdei_error_reason_e {
	SDEI_ERROR_REASON_UNKNOWN		= 0,
	SDEI_ERROR_REASON_SENT_BY_USER		= 1,
	SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE = 2
} sdei_error_reason_t;

#define SDEI_ERROR_REASON__MAX SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE
#define SDEI_ERROR_REASON__MIN SDEI_ERROR_REASON_UNKNOWN

// Bitfield: sdei_error_flags <uint64_t>
typedef struct sdei_error_flags_b {
	// 31:0      sdei_error_reason_t reason
	// 62:32     const uint32_t res0
	// 63        bool system_error
	uint64_t bf[1];
} sdei_error_flags_t;

#define sdei_error_flags_default()                                             \
	(sdei_error_flags_t)                                                   \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define sdei_error_flags_cast(val_0)                                           \
	(sdei_error_flags_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
sdei_error_flags_raw(sdei_error_flags_t bit_field);

void
sdei_error_flags_init(sdei_error_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
sdei_error_flags_t
sdei_error_flags_clean(sdei_error_flags_t bit_field);

bool
sdei_error_flags_is_equal(sdei_error_flags_t b1, sdei_error_flags_t b2);

bool
sdei_error_flags_is_empty(sdei_error_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
sdei_error_flags_is_clean(sdei_error_flags_t bit_field);

typedef enum smccc_arch_function_e {
	SMCCC_ARCH_FUNCTION_VERSION	      = 0,
	SMCCC_ARCH_FUNCTION_ARCH_FEATURES     = 1,
	SMCCC_ARCH_FUNCTION_ARCH_SOC_ID	      = 2,
	SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2 = 32767,
	SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1 = 32768
} smccc_arch_function_t;

#define SMCCC_ARCH_FUNCTION__MAX SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1
#define SMCCC_ARCH_FUNCTION__MIN SMCCC_ARCH_FUNCTION_VERSION

typedef uint16_t smccc_function_t;

typedef enum smccc_owner_id_e {
	SMCCC_OWNER_ID_ARCH	    = 0,
	SMCCC_OWNER_ID_CPU	    = 1,
	SMCCC_OWNER_ID_SIP	    = 2,
	SMCCC_OWNER_ID_OEM	    = 3,
	SMCCC_OWNER_ID_STANDARD	    = 4,
	SMCCC_OWNER_ID_STANDARD_HYP = 5,
	SMCCC_OWNER_ID_VENDOR_HYP   = 6
} smccc_owner_id_t;

#define SMCCC_OWNER_ID__MAX SMCCC_OWNER_ID_VENDOR_HYP
#define SMCCC_OWNER_ID__MIN SMCCC_OWNER_ID_ARCH

// Bitfield: smccc_function_id <uint32_t>
typedef struct smccc_function_id_b {
	// 15:0      smccc_function_t function
	// 16        bool sve_live_state_hint
	// 23:17     const uint32_t res0
	// 29:24     smccc_owner_id_t owner_id
	// 30        bool is_smc64
	// 31        bool is_fast
	uint32_t bf[1];
} smccc_function_id_t;

#define smccc_function_id_default()                                            \
	(smccc_function_id_t)                                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define smccc_function_id_cast(val_0)                                          \
	(smccc_function_id_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
smccc_function_id_raw(smccc_function_id_t bit_field);

void
smccc_function_id_init(smccc_function_id_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
smccc_function_id_t
smccc_function_id_clean(smccc_function_id_t bit_field);

bool
smccc_function_id_is_equal(smccc_function_id_t b1, smccc_function_id_t b2);

bool
smccc_function_id_is_empty(smccc_function_id_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
smccc_function_id_is_clean(smccc_function_id_t bit_field);

typedef enum smccc_standard_hyp_function_e {
	SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES = 32,
	SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST	     = 33,
	SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT	     = 65280,
	SMCCC_STANDARD_HYP_FUNCTION_CALL_UID	     = 65281,
	SMCCC_STANDARD_HYP_FUNCTION_REVISION	     = 65283
} smccc_standard_hyp_function_t;

#define SMCCC_STANDARD_HYP_FUNCTION__MAX SMCCC_STANDARD_HYP_FUNCTION_REVISION
#define SMCCC_STANDARD_HYP_FUNCTION__MIN                                       \
	SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES

typedef enum smccc_vendor_hyp_function_e {
	SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT = 16128,
	SMCCC_VENDOR_HYP_FUNCTION_CALL_UID   = 16129,
	SMCCC_VENDOR_HYP_FUNCTION_REVISION   = 16131
} smccc_vendor_hyp_function_t;

#define SMCCC_VENDOR_HYP_FUNCTION__MAX SMCCC_VENDOR_HYP_FUNCTION_REVISION
#define SMCCC_VENDOR_HYP_FUNCTION__MIN SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT

typedef enum smccc_vendor_hyp_function_class_e {
	SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL = 0,
	SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL     = 2,
	SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE	      = 3
} smccc_vendor_hyp_function_class_t;

#define SMCCC_VENDOR_HYP_FUNCTION_CLASS__MAX                                   \
	SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE
#define SMCCC_VENDOR_HYP_FUNCTION_CLASS__MIN                                   \
	SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL

// Bitfield: smccc_vendor_hyp_function_id <uint16_t>
typedef struct smccc_vendor_hyp_function_id_b {
	// 13:0      uint16_t function
	// 15:14     smccc_vendor_hyp_function_class_t call_class
	uint16_t bf[1];
} smccc_vendor_hyp_function_id_t;

#define smccc_vendor_hyp_function_id_default()                                 \
	(smccc_vendor_hyp_function_id_t)                                       \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define smccc_vendor_hyp_function_id_cast(val_0)                               \
	(smccc_vendor_hyp_function_id_t)                                       \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint16_t
smccc_vendor_hyp_function_id_raw(smccc_vendor_hyp_function_id_t bit_field);

void
smccc_vendor_hyp_function_id_init(smccc_vendor_hyp_function_id_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
smccc_vendor_hyp_function_id_t
smccc_vendor_hyp_function_id_clean(smccc_vendor_hyp_function_id_t bit_field);

bool
smccc_vendor_hyp_function_id_is_equal(smccc_vendor_hyp_function_id_t b1,
				      smccc_vendor_hyp_function_id_t b2);

bool
smccc_vendor_hyp_function_id_is_empty(smccc_vendor_hyp_function_id_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
smccc_vendor_hyp_function_id_is_clean(smccc_vendor_hyp_function_id_t bit_field);

typedef int64_t	 sregister_t;
typedef uint64_t ticks_t;

typedef enum trace_class_e {
	TRACE_CLASS_ERROR	     = 0,
	TRACE_CLASS_DEBUG	     = 1,
	TRACE_CLASS_USER	     = 2,
	TRACE_CLASS_TRACE_LOG_BUFFER = 4,
	TRACE_CLASS_LOG_BUFFER	     = 5,
	TRACE_CLASS_INFO	     = 6,
	TRACE_CLASS_MEMDB	     = 7,
	TRACE_CLASS_VGIC	     = 17,
	TRACE_CLASS_VGIC_DEBUG	     = 18,
	TRACE_CLASS_VGIC_ITS	     = 19
} trace_class_t;

#define TRACE_CLASS__MAX TRACE_CLASS_VGIC_ITS
#define TRACE_CLASS__MIN TRACE_CLASS_ERROR

typedef enum trace_configure_parameter_e {
	TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS	= 0,
	TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE = 1
} trace_configure_parameter_t;

#define TRACE_CONFIGURE_PARAMETER__MAX TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE
#define TRACE_CONFIGURE_PARAMETER__MIN TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS

typedef char *user_ptr_t;

typedef enum vcpu_affinity_type_e {
	VCPU_AFFINITY_TYPE_CPU_INDEX	      = -1,
	VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX = 0
} vcpu_affinity_type_t;

#define VCPU_AFFINITY_TYPE__MAX VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX
#define VCPU_AFFINITY_TYPE__MIN VCPU_AFFINITY_TYPE_CPU_INDEX

typedef enum vcpu_local_virq_type_e {
	VCPU_LOCAL_VIRQ_TYPE_RESERVED	    = 0,
	VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER  = 1,
	VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER = 2
} vcpu_local_virq_type_t;

#define VCPU_LOCAL_VIRQ_TYPE__MAX VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER
#define VCPU_LOCAL_VIRQ_TYPE__MIN VCPU_LOCAL_VIRQ_TYPE_RESERVED

// Bitfield: vcpu_option_flags <uint64_t>
typedef struct vcpu_option_flags_b {
	// 0         bool pinned
	// 1         bool ras_error_handler
	// 2         bool amu_counting_disabled
	// 3         bool sve_allowed
	// 4         bool debug_allowed
	// 5         bool trace_allowed
	// 7         bool mpam_allowed
	// 8         bool critical
	// 9         bool vcpu_run_scheduled
	// 10        bool sme_allowed
	// 11        bool sdei_allowed
	// 63        bool hlos_vm
	uint64_t bf[1];
} vcpu_option_flags_t;

#define vcpu_option_flags_default()                                            \
	(vcpu_option_flags_t)                                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vcpu_option_flags_cast(val_0)                                          \
	(vcpu_option_flags_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vcpu_option_flags_raw(vcpu_option_flags_t bit_field);

void
vcpu_option_flags_init(vcpu_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vcpu_option_flags_t
vcpu_option_flags_clean(vcpu_option_flags_t bit_field);

bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2);

bool
vcpu_option_flags_is_empty(vcpu_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vcpu_option_flags_is_clean(vcpu_option_flags_t bit_field);

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

// Bitfield: vcpu_poweroff_flags <uint64_t>
typedef struct vcpu_poweroff_flags_b {
	// 0         bool last_vcpu
	uint64_t bf[1];
} vcpu_poweroff_flags_t;

#define vcpu_poweroff_flags_default()                                          \
	(vcpu_poweroff_flags_t)                                                \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vcpu_poweroff_flags_cast(val_0)                                        \
	(vcpu_poweroff_flags_t)                                                \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vcpu_poweroff_flags_raw(vcpu_poweroff_flags_t bit_field);

void
vcpu_poweroff_flags_init(vcpu_poweroff_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vcpu_poweroff_flags_t
vcpu_poweroff_flags_clean(vcpu_poweroff_flags_t bit_field);

bool
vcpu_poweroff_flags_is_equal(vcpu_poweroff_flags_t b1,
			     vcpu_poweroff_flags_t b2);

bool
vcpu_poweroff_flags_is_empty(vcpu_poweroff_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vcpu_poweroff_flags_is_clean(vcpu_poweroff_flags_t bit_field);

// Union of boolean fields of two vcpu_poweroff_flags_t values
vcpu_poweroff_flags_t
vcpu_poweroff_flags_union(vcpu_poweroff_flags_t b1, vcpu_poweroff_flags_t b2);

// Intersection of boolean fields of two vcpu_poweroff_flags_t values
vcpu_poweroff_flags_t
vcpu_poweroff_flags_intersection(vcpu_poweroff_flags_t b1,
				 vcpu_poweroff_flags_t b2);

// Invert all boolean fields in a vcpu_poweroff_flags_t value
vcpu_poweroff_flags_t
vcpu_poweroff_flags_inverse(vcpu_poweroff_flags_t b);

// Set difference of boolean fields of two vcpu_poweroff_flags_t values
vcpu_poweroff_flags_t
vcpu_poweroff_flags_difference(vcpu_poweroff_flags_t b1,
			       vcpu_poweroff_flags_t b2);

// Atomically replace a vcpu_poweroff_flags_t value with the union of its
// boolean fields with a given vcpu_poweroff_flags_t value, and return the
// previous value.
vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_union(_Atomic vcpu_poweroff_flags_t *b1,
				 vcpu_poweroff_flags_t b2, memory_order order);

// Atomically replace a vcpu_poweroff_flags_t value with the intersection of its
// boolean fields with a given vcpu_poweroff_flags_t value, and return the
// previous value.
vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_intersection(_Atomic vcpu_poweroff_flags_t *b1,
					vcpu_poweroff_flags_t	       b2,
					memory_order		       order);

// Atomically replace a vcpu_poweroff_flags_t value with the set difference of
// its boolean fields and a given vcpu_poweroff_flags_t value, and return the
// previous value.
vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_difference(_Atomic vcpu_poweroff_flags_t *b1,
				      vcpu_poweroff_flags_t	     b2,
				      memory_order		     order);

// Bitfield: vcpu_poweron_flags <uint64_t>
typedef struct vcpu_poweron_flags_b {
	// 0         bool preserve_entry_point
	// 1         bool preserve_context
	uint64_t bf[1];
} vcpu_poweron_flags_t;

#define vcpu_poweron_flags_default()                                           \
	(vcpu_poweron_flags_t)                                                 \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vcpu_poweron_flags_cast(val_0)                                         \
	(vcpu_poweron_flags_t)                                                 \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vcpu_poweron_flags_raw(vcpu_poweron_flags_t bit_field);

void
vcpu_poweron_flags_init(vcpu_poweron_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vcpu_poweron_flags_t
vcpu_poweron_flags_clean(vcpu_poweron_flags_t bit_field);

bool
vcpu_poweron_flags_is_equal(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2);

bool
vcpu_poweron_flags_is_empty(vcpu_poweron_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vcpu_poweron_flags_is_clean(vcpu_poweron_flags_t bit_field);

// Union of boolean fields of two vcpu_poweron_flags_t values
vcpu_poweron_flags_t
vcpu_poweron_flags_union(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2);

// Intersection of boolean fields of two vcpu_poweron_flags_t values
vcpu_poweron_flags_t
vcpu_poweron_flags_intersection(vcpu_poweron_flags_t b1,
				vcpu_poweron_flags_t b2);

// Invert all boolean fields in a vcpu_poweron_flags_t value
vcpu_poweron_flags_t
vcpu_poweron_flags_inverse(vcpu_poweron_flags_t b);

// Set difference of boolean fields of two vcpu_poweron_flags_t values
vcpu_poweron_flags_t
vcpu_poweron_flags_difference(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2);

// Atomically replace a vcpu_poweron_flags_t value with the union of its boolean
// fields with a given vcpu_poweron_flags_t value, and return the previous
// value.
vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_union(_Atomic vcpu_poweron_flags_t *b1,
				vcpu_poweron_flags_t b2, memory_order order);

// Atomically replace a vcpu_poweron_flags_t value with the intersection of its
// boolean fields with a given vcpu_poweron_flags_t value, and return the
// previous value.
vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_intersection(_Atomic vcpu_poweron_flags_t *b1,
				       vcpu_poweron_flags_t	     b2,
				       memory_order		     order);

// Atomically replace a vcpu_poweron_flags_t value with the set difference of
// its boolean fields and a given vcpu_poweron_flags_t value, and return the
// previous value.
vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_difference(_Atomic vcpu_poweron_flags_t *b1,
				     vcpu_poweron_flags_t	   b2,
				     memory_order		   order);

typedef enum vcpu_register_set_e {
	VCPU_REGISTER_SET_X	= 0,
	VCPU_REGISTER_SET_PC	= 1,
	VCPU_REGISTER_SET_SP_EL = 2
} vcpu_register_set_t;

#define VCPU_REGISTER_SET__MAX VCPU_REGISTER_SET_SP_EL
#define VCPU_REGISTER_SET__MIN VCPU_REGISTER_SET_X

// Bitfield: vcpu_run_poweroff_flags <uint32_t>
typedef struct vcpu_run_poweroff_flags_b {
	// 0         bool exited
	uint32_t bf[1];
} vcpu_run_poweroff_flags_t;

#define vcpu_run_poweroff_flags_default()                                      \
	(vcpu_run_poweroff_flags_t)                                            \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vcpu_run_poweroff_flags_cast(val_0)                                    \
	(vcpu_run_poweroff_flags_t)                                            \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint32_t
vcpu_run_poweroff_flags_raw(vcpu_run_poweroff_flags_t bit_field);

void
vcpu_run_poweroff_flags_init(vcpu_run_poweroff_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_clean(vcpu_run_poweroff_flags_t bit_field);

bool
vcpu_run_poweroff_flags_is_equal(vcpu_run_poweroff_flags_t b1,
				 vcpu_run_poweroff_flags_t b2);

bool
vcpu_run_poweroff_flags_is_empty(vcpu_run_poweroff_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vcpu_run_poweroff_flags_is_clean(vcpu_run_poweroff_flags_t bit_field);

// Union of boolean fields of two vcpu_run_poweroff_flags_t values
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_union(vcpu_run_poweroff_flags_t b1,
			      vcpu_run_poweroff_flags_t b2);

// Intersection of boolean fields of two vcpu_run_poweroff_flags_t values
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_intersection(vcpu_run_poweroff_flags_t b1,
				     vcpu_run_poweroff_flags_t b2);

// Invert all boolean fields in a vcpu_run_poweroff_flags_t value
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_inverse(vcpu_run_poweroff_flags_t b);

// Set difference of boolean fields of two vcpu_run_poweroff_flags_t values
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_difference(vcpu_run_poweroff_flags_t b1,
				   vcpu_run_poweroff_flags_t b2);

// Atomically replace a vcpu_run_poweroff_flags_t value with the union of its
// boolean fields with a given vcpu_run_poweroff_flags_t value, and return the
// previous value.
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_union(_Atomic vcpu_run_poweroff_flags_t *b1,
				     vcpu_run_poweroff_flags_t		b2,
				     memory_order			order);

// Atomically replace a vcpu_run_poweroff_flags_t value with the intersection of
// its boolean fields with a given vcpu_run_poweroff_flags_t value, and return
// the previous value.
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_intersection(
	_Atomic vcpu_run_poweroff_flags_t *b1, vcpu_run_poweroff_flags_t b2,
	memory_order order);

// Atomically replace a vcpu_run_poweroff_flags_t value with the set difference
// of its boolean fields and a given vcpu_run_poweroff_flags_t value, and return
// the previous value.
vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_difference(_Atomic vcpu_run_poweroff_flags_t *b1,
					  vcpu_run_poweroff_flags_t	     b2,
					  memory_order order);

typedef enum vcpu_run_state_e {
	VCPU_RUN_STATE_READY		     = 0,
	VCPU_RUN_STATE_EXPECTS_WAKEUP	     = 1,
	VCPU_RUN_STATE_POWERED_OFF	     = 2,
	VCPU_RUN_STATE_BLOCKED		     = 3,
	VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ  = 4,
	VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE = 5,
	VCPU_RUN_STATE_FAULT		     = 6,
	VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT  = 7,
	VCPU_RUN_STATE_PSCI_SYSTEM_RESET     = 256
} vcpu_run_state_t;

#define VCPU_RUN_STATE__MAX VCPU_RUN_STATE_PSCI_SYSTEM_RESET
#define VCPU_RUN_STATE__MIN VCPU_RUN_STATE_READY

typedef enum vcpu_run_wakeup_from_state_e {
	VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED	       = 0,
	VCPU_RUN_WAKEUP_FROM_STATE_WFI		       = 1,
	VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND    = 2,
	VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND = 3
} vcpu_run_wakeup_from_state_t;

#define VCPU_RUN_WAKEUP_FROM_STATE__MAX                                        \
	VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND
#define VCPU_RUN_WAKEUP_FROM_STATE__MIN VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED

typedef enum vcpu_virq_type_e {
	VCPU_VIRQ_TYPE_HALT	       = 0,
	VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP = 1
} vcpu_virq_type_t;

#define VCPU_VIRQ_TYPE__MAX VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP
#define VCPU_VIRQ_TYPE__MIN VCPU_VIRQ_TYPE_HALT

typedef uint32_t vgic_device_id_t;

// Bitfield: vic_msi_source_config <uint64_t>
typedef struct vic_msi_source_config_b {
	// 15:0      uint16_t index
	// 63:16     const uint64_t res0
	uint64_t bf[1];
} vic_msi_source_config_t;

#define vic_msi_source_config_default()                                        \
	(vic_msi_source_config_t)                                              \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vic_msi_source_config_cast(val_0)                                      \
	(vic_msi_source_config_t)                                              \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vic_msi_source_config_raw(vic_msi_source_config_t bit_field);

void
vic_msi_source_config_init(vic_msi_source_config_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vic_msi_source_config_t
vic_msi_source_config_clean(vic_msi_source_config_t bit_field);

bool
vic_msi_source_config_is_equal(vic_msi_source_config_t b1,
			       vic_msi_source_config_t b2);

bool
vic_msi_source_config_is_empty(vic_msi_source_config_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vic_msi_source_config_is_clean(vic_msi_source_config_t bit_field);

// Bitfield: vic_option_flags <uint64_t>
typedef struct vic_option_flags_b {
	// 0         bool max_msis_valid
	// 1         bool disable_default_addr
	// 63:2      uint64_t res0_0
	uint64_t bf[1];
} vic_option_flags_t;

#define vic_option_flags_default()                                             \
	(vic_option_flags_t)                                                   \
	{                                                                      \
		.bf = { 0x3U }                                                 \
	}

#define vic_option_flags_cast(val_0)                                           \
	(vic_option_flags_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vic_option_flags_raw(vic_option_flags_t bit_field);

void
vic_option_flags_init(vic_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vic_option_flags_t
vic_option_flags_clean(vic_option_flags_t bit_field);

bool
vic_option_flags_is_equal(vic_option_flags_t b1, vic_option_flags_t b2);

bool
vic_option_flags_is_empty(vic_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vic_option_flags_is_clean(vic_option_flags_t bit_field);

typedef uint64_t viommu_stream_id_t;

typedef enum virtio_device_type_e {
	VIRTIO_DEVICE_TYPE_INVALID = 0,
	VIRTIO_DEVICE_TYPE_NETWORK = 1,
	VIRTIO_DEVICE_TYPE_BLOCK   = 2,
	VIRTIO_DEVICE_TYPE_CONSOLE = 3,
	VIRTIO_DEVICE_TYPE_BALLOON = 13,
	VIRTIO_DEVICE_TYPE_GPU	   = 16,
	VIRTIO_DEVICE_TYPE_INPUT   = 18,
	VIRTIO_DEVICE_TYPE_SOCKET  = 19,
	VIRTIO_DEVICE_TYPE_IOMMU   = 23,
	VIRTIO_DEVICE_TYPE_MEMORY  = 24
} virtio_device_type_t;

#define VIRTIO_DEVICE_TYPE__MAX VIRTIO_DEVICE_TYPE_MEMORY
#define VIRTIO_DEVICE_TYPE__MIN VIRTIO_DEVICE_TYPE_INVALID

typedef enum virtio_transport_type_e {
	VIRTIO_TRANSPORT_TYPE_MMIO = 0,
	VIRTIO_TRANSPORT_TYPE_PCI  = 1
} virtio_transport_type_t;

#define VIRTIO_TRANSPORT_TYPE__MAX VIRTIO_TRANSPORT_TYPE_PCI
#define VIRTIO_TRANSPORT_TYPE__MIN VIRTIO_TRANSPORT_TYPE_MMIO

// Bitfield: virtio_backend_interface_type <uint64_t>
typedef struct virtio_backend_interface_type_b {
	// 7:0       virtio_device_type_t device
	// 23:16     virtio_transport_type_t transport
	uint64_t bf[1];
} virtio_backend_interface_type_t;

#define virtio_backend_interface_type_default()                                \
	(virtio_backend_interface_type_t)                                      \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_backend_interface_type_cast(val_0)                              \
	(virtio_backend_interface_type_t)                                      \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_interface_type_raw(virtio_backend_interface_type_t bit_field);

void
virtio_backend_interface_type_init(virtio_backend_interface_type_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_interface_type_t
virtio_backend_interface_type_clean(virtio_backend_interface_type_t bit_field);

bool
virtio_backend_interface_type_is_equal(virtio_backend_interface_type_t b1,
				       virtio_backend_interface_type_t b2);

bool
virtio_backend_interface_type_is_empty(
	virtio_backend_interface_type_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_interface_type_is_clean(
	virtio_backend_interface_type_t bit_field);

// Bitfield: virtio_backend_interrupt_perqueue <uint64_t>
typedef struct virtio_backend_interrupt_perqueue_b {
	// 15:0      uint64_t queues_ready
	// 63        bool config_update
	uint64_t bf[1];
} virtio_backend_interrupt_perqueue_t;

#define virtio_backend_interrupt_perqueue_default()                            \
	(virtio_backend_interrupt_perqueue_t)                                  \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_backend_interrupt_perqueue_cast(val_0)                          \
	(virtio_backend_interrupt_perqueue_t)                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_interrupt_perqueue_raw(
	virtio_backend_interrupt_perqueue_t bit_field);

void
virtio_backend_interrupt_perqueue_init(
	virtio_backend_interrupt_perqueue_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_interrupt_perqueue_t
virtio_backend_interrupt_perqueue_clean(
	virtio_backend_interrupt_perqueue_t bit_field);

bool
virtio_backend_interrupt_perqueue_is_equal(
	virtio_backend_interrupt_perqueue_t b1,
	virtio_backend_interrupt_perqueue_t b2);

bool
virtio_backend_interrupt_perqueue_is_empty(
	virtio_backend_interrupt_perqueue_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_interrupt_perqueue_is_clean(
	virtio_backend_interrupt_perqueue_t bit_field);

// Bitfield: virtio_backend_memextent_layout <uint64_t>
typedef struct virtio_backend_memextent_layout_b {
	// 15:0      size_t devcfg_size
	// 32:16     size_t devcfg_offset
	uint64_t bf[1];
} virtio_backend_memextent_layout_t;

#define virtio_backend_memextent_layout_default()                              \
	(virtio_backend_memextent_layout_t)                                    \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_backend_memextent_layout_cast(val_0)                            \
	(virtio_backend_memextent_layout_t)                                    \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_memextent_layout_raw(virtio_backend_memextent_layout_t bit_field);

void
virtio_backend_memextent_layout_init(
	virtio_backend_memextent_layout_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_memextent_layout_t
virtio_backend_memextent_layout_clean(
	virtio_backend_memextent_layout_t bit_field);

bool
virtio_backend_memextent_layout_is_equal(virtio_backend_memextent_layout_t b1,
					 virtio_backend_memextent_layout_t b2);

bool
virtio_backend_memextent_layout_is_empty(
	virtio_backend_memextent_layout_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_memextent_layout_is_clean(
	virtio_backend_memextent_layout_t bit_field);

// Bitfield: virtio_backend_notify_flags <uint64_t>
typedef struct virtio_backend_notify_flags_b {
	// 0         bool per_queue
	// 1         bool config_update
	uint64_t bf[1];
} virtio_backend_notify_flags_t;

#define virtio_backend_notify_flags_default()                                  \
	(virtio_backend_notify_flags_t)                                        \
	{                                                                      \
		.bf = { 0x1U }                                                 \
	}

#define virtio_backend_notify_flags_cast(val_0)                                \
	(virtio_backend_notify_flags_t)                                        \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_notify_flags_raw(virtio_backend_notify_flags_t bit_field);

void
virtio_backend_notify_flags_init(virtio_backend_notify_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_notify_flags_t
virtio_backend_notify_flags_clean(virtio_backend_notify_flags_t bit_field);

bool
virtio_backend_notify_flags_is_equal(virtio_backend_notify_flags_t b1,
				     virtio_backend_notify_flags_t b2);

bool
virtio_backend_notify_flags_is_empty(virtio_backend_notify_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_notify_flags_is_clean(virtio_backend_notify_flags_t bit_field);

// Union of boolean fields of two virtio_backend_notify_flags_t values
virtio_backend_notify_flags_t
virtio_backend_notify_flags_union(virtio_backend_notify_flags_t b1,
				  virtio_backend_notify_flags_t b2);

// Intersection of boolean fields of two virtio_backend_notify_flags_t values
virtio_backend_notify_flags_t
virtio_backend_notify_flags_intersection(virtio_backend_notify_flags_t b1,
					 virtio_backend_notify_flags_t b2);

// Invert all boolean fields in a virtio_backend_notify_flags_t value
virtio_backend_notify_flags_t
virtio_backend_notify_flags_inverse(virtio_backend_notify_flags_t b);

// Set difference of boolean fields of two virtio_backend_notify_flags_t values
virtio_backend_notify_flags_t
virtio_backend_notify_flags_difference(virtio_backend_notify_flags_t b1,
				       virtio_backend_notify_flags_t b2);

// Atomically replace a virtio_backend_notify_flags_t value with the union of
// its boolean fields with a given virtio_backend_notify_flags_t value, and
// return the previous value.
virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_union(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order);

// Atomically replace a virtio_backend_notify_flags_t value with the
// intersection of its boolean fields with a given virtio_backend_notify_flags_t
// value, and return the previous value.
virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_intersection(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order);

// Atomically replace a virtio_backend_notify_flags_t value with the set
// difference of its boolean fields and a given virtio_backend_notify_flags_t
// value, and return the previous value.
virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_difference(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order);

// Bitfield: virtio_backend_notify_reason <uint64_t>
typedef struct virtio_backend_notify_reason_b {
	// 0         bool new_buffer
	// 1         bool reset_request
	// 2         const bool res0_2
	// 3         bool driver_ok
	// 4         bool failed
	uint64_t bf[1];
} virtio_backend_notify_reason_t;

#define virtio_backend_notify_reason_default()                                 \
	(virtio_backend_notify_reason_t)                                       \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_backend_notify_reason_cast(val_0)                               \
	(virtio_backend_notify_reason_t)                                       \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_notify_reason_raw(virtio_backend_notify_reason_t bit_field);

void
virtio_backend_notify_reason_init(virtio_backend_notify_reason_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_notify_reason_t
virtio_backend_notify_reason_clean(virtio_backend_notify_reason_t bit_field);

bool
virtio_backend_notify_reason_is_equal(virtio_backend_notify_reason_t b1,
				      virtio_backend_notify_reason_t b2);

bool
virtio_backend_notify_reason_is_empty(virtio_backend_notify_reason_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_notify_reason_is_clean(virtio_backend_notify_reason_t bit_field);

// Union of boolean fields of two virtio_backend_notify_reason_t values
virtio_backend_notify_reason_t
virtio_backend_notify_reason_union(virtio_backend_notify_reason_t b1,
				   virtio_backend_notify_reason_t b2);

// Intersection of boolean fields of two virtio_backend_notify_reason_t values
virtio_backend_notify_reason_t
virtio_backend_notify_reason_intersection(virtio_backend_notify_reason_t b1,
					  virtio_backend_notify_reason_t b2);

// Invert all boolean fields in a virtio_backend_notify_reason_t value
virtio_backend_notify_reason_t
virtio_backend_notify_reason_inverse(virtio_backend_notify_reason_t b);

// Set difference of boolean fields of two virtio_backend_notify_reason_t values
virtio_backend_notify_reason_t
virtio_backend_notify_reason_difference(virtio_backend_notify_reason_t b1,
					virtio_backend_notify_reason_t b2);

// Atomically replace a virtio_backend_notify_reason_t value with the union of
// its boolean fields with a given virtio_backend_notify_reason_t value, and
// return the previous value.
virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_union(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order);

// Atomically replace a virtio_backend_notify_reason_t value with the
// intersection of its boolean fields with a given
// virtio_backend_notify_reason_t value, and return the previous value.
virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_intersection(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order);

// Atomically replace a virtio_backend_notify_reason_t value with the set
// difference of its boolean fields and a given virtio_backend_notify_reason_t
// value, and return the previous value.
virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_difference(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order);

// Bitfield: virtio_interrupt <uint8_t>
typedef struct virtio_interrupt_b {
	// 0         bool queue_ready
	// 1         bool config_update
	uint8_t bf[1];
} virtio_interrupt_t;

#define virtio_interrupt_default()                                             \
	(virtio_interrupt_t)                                                   \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_interrupt_cast(val_0)                                           \
	(virtio_interrupt_t)                                                   \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint8_t
virtio_interrupt_raw(virtio_interrupt_t bit_field);

void
virtio_interrupt_init(virtio_interrupt_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_interrupt_t
virtio_interrupt_clean(virtio_interrupt_t bit_field);

bool
virtio_interrupt_is_equal(virtio_interrupt_t b1, virtio_interrupt_t b2);

bool
virtio_interrupt_is_empty(virtio_interrupt_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_interrupt_is_clean(virtio_interrupt_t bit_field);

// Union of boolean fields of two virtio_interrupt_t values
virtio_interrupt_t
virtio_interrupt_union(virtio_interrupt_t b1, virtio_interrupt_t b2);

// Intersection of boolean fields of two virtio_interrupt_t values
virtio_interrupt_t
virtio_interrupt_intersection(virtio_interrupt_t b1, virtio_interrupt_t b2);

// Invert all boolean fields in a virtio_interrupt_t value
virtio_interrupt_t
virtio_interrupt_inverse(virtio_interrupt_t b);

// Set difference of boolean fields of two virtio_interrupt_t values
virtio_interrupt_t
virtio_interrupt_difference(virtio_interrupt_t b1, virtio_interrupt_t b2);

// Atomically replace a virtio_interrupt_t value with the union of its boolean
// fields with a given virtio_interrupt_t value, and return the previous value.
virtio_interrupt_t
virtio_interrupt_atomic_union(_Atomic virtio_interrupt_t *b1,
			      virtio_interrupt_t b2, memory_order order);

// Atomically replace a virtio_interrupt_t value with the intersection of its
// boolean fields with a given virtio_interrupt_t value, and return the previous
// value.
virtio_interrupt_t
virtio_interrupt_atomic_intersection(_Atomic virtio_interrupt_t *b1,
				     virtio_interrupt_t b2, memory_order order);

// Atomically replace a virtio_interrupt_t value with the set difference of its
// boolean fields and a given virtio_interrupt_t value, and return the previous
// value.
virtio_interrupt_t
virtio_interrupt_atomic_difference(_Atomic virtio_interrupt_t *b1,
				   virtio_interrupt_t b2, memory_order order);

union virtio_backend_notify_status_u {
	virtio_interrupt_t		    unified;
	virtio_backend_interrupt_perqueue_t per_queue;
	uint64_t			    raw;
};

// Bitfield: virtio_backend_option_flags <uint64_t>
typedef struct virtio_backend_option_flags_b {
	// 0         bool sync_reset
	// 1         bool per_queue_irqs
	// 2         bool ignore_config_writes
	// 3         bool valid_me_layout
	// 6         bool valid_type
	uint64_t bf[1];
} virtio_backend_option_flags_t;

#define virtio_backend_option_flags_default()                                  \
	(virtio_backend_option_flags_t)                                        \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define virtio_backend_option_flags_cast(val_0)                                \
	(virtio_backend_option_flags_t)                                        \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_backend_option_flags_raw(virtio_backend_option_flags_t bit_field);

void
virtio_backend_option_flags_init(virtio_backend_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_backend_option_flags_t
virtio_backend_option_flags_clean(virtio_backend_option_flags_t bit_field);

bool
virtio_backend_option_flags_is_equal(virtio_backend_option_flags_t b1,
				     virtio_backend_option_flags_t b2);

bool
virtio_backend_option_flags_is_empty(virtio_backend_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_backend_option_flags_is_clean(virtio_backend_option_flags_t bit_field);

// Union of boolean fields of two virtio_backend_option_flags_t values
virtio_backend_option_flags_t
virtio_backend_option_flags_union(virtio_backend_option_flags_t b1,
				  virtio_backend_option_flags_t b2);

// Intersection of boolean fields of two virtio_backend_option_flags_t values
virtio_backend_option_flags_t
virtio_backend_option_flags_intersection(virtio_backend_option_flags_t b1,
					 virtio_backend_option_flags_t b2);

// Invert all boolean fields in a virtio_backend_option_flags_t value
virtio_backend_option_flags_t
virtio_backend_option_flags_inverse(virtio_backend_option_flags_t b);

// Set difference of boolean fields of two virtio_backend_option_flags_t values
virtio_backend_option_flags_t
virtio_backend_option_flags_difference(virtio_backend_option_flags_t b1,
				       virtio_backend_option_flags_t b2);

// Atomically replace a virtio_backend_option_flags_t value with the union of
// its boolean fields with a given virtio_backend_option_flags_t value, and
// return the previous value.
virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_union(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order);

// Atomically replace a virtio_backend_option_flags_t value with the
// intersection of its boolean fields with a given virtio_backend_option_flags_t
// value, and return the previous value.
virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_intersection(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order);

// Atomically replace a virtio_backend_option_flags_t value with the set
// difference of its boolean fields and a given virtio_backend_option_flags_t
// value, and return the previous value.
virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_difference(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order);

// Bitfield: virtio_iommu_options <uint64_t>
typedef struct virtio_iommu_options_b {
	// 31:0      count_t max_streams
	// 32        const bool addrspace_valid
	uint64_t bf[1];
} virtio_iommu_options_t;

#define virtio_iommu_options_default()                                         \
	(virtio_iommu_options_t)                                               \
	{                                                                      \
		.bf = { 0x100000000U }                                         \
	}

#define virtio_iommu_options_cast(val_0)                                       \
	(virtio_iommu_options_t)                                               \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
virtio_iommu_options_raw(virtio_iommu_options_t bit_field);

void
virtio_iommu_options_init(virtio_iommu_options_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_iommu_options_t
virtio_iommu_options_clean(virtio_iommu_options_t bit_field);

bool
virtio_iommu_options_is_equal(virtio_iommu_options_t b1,
			      virtio_iommu_options_t b2);

bool
virtio_iommu_options_is_empty(virtio_iommu_options_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_iommu_options_is_clean(virtio_iommu_options_t bit_field);

// Bitfield: virtio_status <uint8_t>
typedef struct virtio_status_b {
	// 0         bool acknowledge
	// 1         bool driver
	// 2         bool driver_ok
	// 3         bool features_ok
	// 6         bool device_needs_reset
	// 7         bool failed
	uint8_t bf[1];
} virtio_status_t;

#define virtio_status_default()                                                \
	(virtio_status_t)                                                      \
	{                                                                      \
		.bf = { 0x40U }                                                \
	}

#define virtio_status_cast(val_0)                                              \
	(virtio_status_t)                                                      \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint8_t
virtio_status_raw(virtio_status_t bit_field);

void
virtio_status_init(virtio_status_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
virtio_status_t
virtio_status_clean(virtio_status_t bit_field);

bool
virtio_status_is_equal(virtio_status_t b1, virtio_status_t b2);

bool
virtio_status_is_empty(virtio_status_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
virtio_status_is_clean(virtio_status_t bit_field);

// Union of boolean fields of two virtio_status_t values
virtio_status_t
virtio_status_union(virtio_status_t b1, virtio_status_t b2);

// Intersection of boolean fields of two virtio_status_t values
virtio_status_t
virtio_status_intersection(virtio_status_t b1, virtio_status_t b2);

// Invert all boolean fields in a virtio_status_t value
virtio_status_t
virtio_status_inverse(virtio_status_t b);

// Set difference of boolean fields of two virtio_status_t values
virtio_status_t
virtio_status_difference(virtio_status_t b1, virtio_status_t b2);

// Atomically replace a virtio_status_t value with the union of its boolean
// fields with a given virtio_status_t value, and return the previous value.
virtio_status_t
virtio_status_atomic_union(_Atomic virtio_status_t *b1, virtio_status_t b2,
			   memory_order order);

// Atomically replace a virtio_status_t value with the intersection of its
// boolean fields with a given virtio_status_t value, and return the previous
// value.
virtio_status_t
virtio_status_atomic_intersection(_Atomic virtio_status_t *b1,
				  virtio_status_t b2, memory_order order);

// Atomically replace a virtio_status_t value with the set difference of its
// boolean fields and a given virtio_status_t value, and return the previous
// value.
virtio_status_t
virtio_status_atomic_difference(_Atomic virtio_status_t *b1, virtio_status_t b2,
				memory_order order);
typedef uint16_t vmid_t;

// Bitfield: vpci_aperture <uint64_t>
typedef struct vpci_aperture_b {
	// 5:0       count_t bits
	// 11:6      const uint64_t res0
	// 63:12     vmaddr_t base
	uint64_t bf[1];
} vpci_aperture_t;

#define vpci_aperture_default()                                                \
	(vpci_aperture_t)                                                      \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vpci_aperture_cast(val_0)                                              \
	(vpci_aperture_t)                                                      \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vpci_aperture_raw(vpci_aperture_t bit_field);

void
vpci_aperture_init(vpci_aperture_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vpci_aperture_t
vpci_aperture_clean(vpci_aperture_t bit_field);

bool
vpci_aperture_is_equal(vpci_aperture_t b1, vpci_aperture_t b2);

bool
vpci_aperture_is_empty(vpci_aperture_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vpci_aperture_is_clean(vpci_aperture_t bit_field);

// Bitfield: vpci_option_flags <uint64_t>
typedef struct vpci_option_flags_b {
	// 0         bool pcie
	// 63:1      const uint64_t res0
	uint64_t bf[1];
} vpci_option_flags_t;

#define vpci_option_flags_default()                                            \
	(vpci_option_flags_t)                                                  \
	{                                                                      \
		.bf = { 0x1U }                                                 \
	}

#define vpci_option_flags_cast(val_0)                                          \
	(vpci_option_flags_t)                                                  \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vpci_option_flags_raw(vpci_option_flags_t bit_field);

void
vpci_option_flags_init(vpci_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vpci_option_flags_t
vpci_option_flags_clean(vpci_option_flags_t bit_field);

bool
vpci_option_flags_is_equal(vpci_option_flags_t b1, vpci_option_flags_t b2);

bool
vpci_option_flags_is_empty(vpci_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vpci_option_flags_is_clean(vpci_option_flags_t bit_field);

// Bitfield: vpm_group_option_flags <uint64_t>
typedef struct vpm_group_option_flags_b {
	// 0         bool no_aggregation
	// 1         bool explicit_wakeup
	uint64_t bf[1];
} vpm_group_option_flags_t;

#define vpm_group_option_flags_default()                                       \
	(vpm_group_option_flags_t)                                             \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define vpm_group_option_flags_cast(val_0)                                     \
	(vpm_group_option_flags_t)                                             \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
vpm_group_option_flags_raw(vpm_group_option_flags_t bit_field);

void
vpm_group_option_flags_init(vpm_group_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
vpm_group_option_flags_t
vpm_group_option_flags_clean(vpm_group_option_flags_t bit_field);

bool
vpm_group_option_flags_is_equal(vpm_group_option_flags_t b1,
				vpm_group_option_flags_t b2);

bool
vpm_group_option_flags_is_empty(vpm_group_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
vpm_group_option_flags_is_clean(vpm_group_option_flags_t bit_field);

// Union of boolean fields of two vpm_group_option_flags_t values
vpm_group_option_flags_t
vpm_group_option_flags_union(vpm_group_option_flags_t b1,
			     vpm_group_option_flags_t b2);

// Intersection of boolean fields of two vpm_group_option_flags_t values
vpm_group_option_flags_t
vpm_group_option_flags_intersection(vpm_group_option_flags_t b1,
				    vpm_group_option_flags_t b2);

// Invert all boolean fields in a vpm_group_option_flags_t value
vpm_group_option_flags_t
vpm_group_option_flags_inverse(vpm_group_option_flags_t b);

// Set difference of boolean fields of two vpm_group_option_flags_t values
vpm_group_option_flags_t
vpm_group_option_flags_difference(vpm_group_option_flags_t b1,
				  vpm_group_option_flags_t b2);

// Atomically replace a vpm_group_option_flags_t value with the union of its
// boolean fields with a given vpm_group_option_flags_t value, and return the
// previous value.
vpm_group_option_flags_t
vpm_group_option_flags_atomic_union(_Atomic vpm_group_option_flags_t *b1,
				    vpm_group_option_flags_t	      b2,
				    memory_order		      order);

// Atomically replace a vpm_group_option_flags_t value with the intersection of
// its boolean fields with a given vpm_group_option_flags_t value, and return
// the previous value.
vpm_group_option_flags_t
vpm_group_option_flags_atomic_intersection(_Atomic vpm_group_option_flags_t *b1,
					   vpm_group_option_flags_t	     b2,
					   memory_order order);

// Atomically replace a vpm_group_option_flags_t value with the set difference
// of its boolean fields and a given vpm_group_option_flags_t value, and return
// the previous value.
vpm_group_option_flags_t
vpm_group_option_flags_atomic_difference(_Atomic vpm_group_option_flags_t *b1,
					 vpm_group_option_flags_t	   b2,
					 memory_order order);

typedef enum vpm_state_e {
	VPM_STATE_NO_STATE	   = 0,
	VPM_STATE_RUNNING	   = 1,
	VPM_STATE_CPUS_SUSPENDED   = 2,
	VPM_STATE_SYSTEM_SUSPENDED = 3
} vpm_state_t;

#define VPM_STATE__MAX VPM_STATE_SYSTEM_SUSPENDED
#define VPM_STATE__MIN VPM_STATE_NO_STATE

// Bitfield: watchdog_bind_option_flags <uint64_t>
typedef struct watchdog_bind_option_flags_b {
	// 0         bool bite_virq
	uint64_t bf[1];
} watchdog_bind_option_flags_t;

#define watchdog_bind_option_flags_default()                                   \
	(watchdog_bind_option_flags_t)                                         \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define watchdog_bind_option_flags_cast(val_0)                                 \
	(watchdog_bind_option_flags_t)                                         \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
watchdog_bind_option_flags_raw(watchdog_bind_option_flags_t bit_field);

void
watchdog_bind_option_flags_init(watchdog_bind_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
watchdog_bind_option_flags_t
watchdog_bind_option_flags_clean(watchdog_bind_option_flags_t bit_field);

bool
watchdog_bind_option_flags_is_equal(watchdog_bind_option_flags_t b1,
				    watchdog_bind_option_flags_t b2);

bool
watchdog_bind_option_flags_is_empty(watchdog_bind_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
watchdog_bind_option_flags_is_clean(watchdog_bind_option_flags_t bit_field);

// Union of boolean fields of two watchdog_bind_option_flags_t values
watchdog_bind_option_flags_t
watchdog_bind_option_flags_union(watchdog_bind_option_flags_t b1,
				 watchdog_bind_option_flags_t b2);

// Intersection of boolean fields of two watchdog_bind_option_flags_t values
watchdog_bind_option_flags_t
watchdog_bind_option_flags_intersection(watchdog_bind_option_flags_t b1,
					watchdog_bind_option_flags_t b2);

// Invert all boolean fields in a watchdog_bind_option_flags_t value
watchdog_bind_option_flags_t
watchdog_bind_option_flags_inverse(watchdog_bind_option_flags_t b);

// Set difference of boolean fields of two watchdog_bind_option_flags_t values
watchdog_bind_option_flags_t
watchdog_bind_option_flags_difference(watchdog_bind_option_flags_t b1,
				      watchdog_bind_option_flags_t b2);

// Atomically replace a watchdog_bind_option_flags_t value with the union of its
// boolean fields with a given watchdog_bind_option_flags_t value, and return
// the previous value.
watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_union(_Atomic watchdog_bind_option_flags_t *b1,
					watchdog_bind_option_flags_t b2,
					memory_order		     order);

// Atomically replace a watchdog_bind_option_flags_t value with the intersection
// of its boolean fields with a given watchdog_bind_option_flags_t value, and
// return the previous value.
watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_intersection(
	_Atomic watchdog_bind_option_flags_t *b1,
	watchdog_bind_option_flags_t b2, memory_order order);

// Atomically replace a watchdog_bind_option_flags_t value with the set
// difference of its boolean fields and a given watchdog_bind_option_flags_t
// value, and return the previous value.
watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_difference(
	_Atomic watchdog_bind_option_flags_t *b1,
	watchdog_bind_option_flags_t b2, memory_order order);

typedef enum watchdog_manage_op_e {
	WATCHDOG_MANAGE_OP_FREEZE	    = 0,
	WATCHDOG_MANAGE_OP_FREEZE_AND_RESET = 1,
	WATCHDOG_MANAGE_OP_UNFREEZE	    = 2
} watchdog_manage_op_t;

#define WATCHDOG_MANAGE_OP__MAX WATCHDOG_MANAGE_OP_UNFREEZE
#define WATCHDOG_MANAGE_OP__MIN WATCHDOG_MANAGE_OP_FREEZE

// Bitfield: watchdog_option_flags <uint64_t>
typedef struct watchdog_option_flags_b {
	// 0         bool critical_bite
	// 1         bool fatal_bite
	uint64_t bf[1];
} watchdog_option_flags_t;

#define watchdog_option_flags_default()                                        \
	(watchdog_option_flags_t)                                              \
	{                                                                      \
		.bf = { 0x0U }                                                 \
	}

#define watchdog_option_flags_cast(val_0)                                      \
	(watchdog_option_flags_t)                                              \
	{                                                                      \
		.bf = {(val_0) }                                               \
	}

uint64_t
watchdog_option_flags_raw(watchdog_option_flags_t bit_field);

void
watchdog_option_flags_init(watchdog_option_flags_t *bit_field);

// Set all unknown/unnamed fields to their expected default values.
// Note, this does NOT clean const named fields to default values.
watchdog_option_flags_t
watchdog_option_flags_clean(watchdog_option_flags_t bit_field);

bool
watchdog_option_flags_is_equal(watchdog_option_flags_t b1,
			       watchdog_option_flags_t b2);

bool
watchdog_option_flags_is_empty(watchdog_option_flags_t bit_field);

// Check all unknown/unnamed fields have expected default values.
// Note, this does NOT check:
// - whether const named fields have their default values,
// - whether named fields with enumerated types are in-range, or
// - the values of named writeonly fields.
bool
watchdog_option_flags_is_clean(watchdog_option_flags_t bit_field);

// Union of boolean fields of two watchdog_option_flags_t values
watchdog_option_flags_t
watchdog_option_flags_union(watchdog_option_flags_t b1,
			    watchdog_option_flags_t b2);

// Intersection of boolean fields of two watchdog_option_flags_t values
watchdog_option_flags_t
watchdog_option_flags_intersection(watchdog_option_flags_t b1,
				   watchdog_option_flags_t b2);

// Invert all boolean fields in a watchdog_option_flags_t value
watchdog_option_flags_t
watchdog_option_flags_inverse(watchdog_option_flags_t b);

// Set difference of boolean fields of two watchdog_option_flags_t values
watchdog_option_flags_t
watchdog_option_flags_difference(watchdog_option_flags_t b1,
				 watchdog_option_flags_t b2);

// Atomically replace a watchdog_option_flags_t value with the union of its
// boolean fields with a given watchdog_option_flags_t value, and return the
// previous value.
watchdog_option_flags_t
watchdog_option_flags_atomic_union(_Atomic watchdog_option_flags_t *b1,
				   watchdog_option_flags_t	    b2,
				   memory_order			    order);

// Atomically replace a watchdog_option_flags_t value with the intersection of
// its boolean fields with a given watchdog_option_flags_t value, and return the
// previous value.
watchdog_option_flags_t
watchdog_option_flags_atomic_intersection(_Atomic watchdog_option_flags_t *b1,
					  watchdog_option_flags_t	   b2,
					  memory_order order);

// Atomically replace a watchdog_option_flags_t value with the set difference of
// its boolean fields and a given watchdog_option_flags_t value, and return the
// previous value.
watchdog_option_flags_t
watchdog_option_flags_atomic_difference(_Atomic watchdog_option_flags_t *b1,
					watchdog_option_flags_t		 b2,
					memory_order			 order);

#include <guest_hypresult.h>

addrspace_access_type_t
addrspace_access_type_raw_cast(uint32_t val);

#define addrspace_access_type_cast(val)                                        \
	addrspace_access_type_raw_cast((uint32_t)(val))

addrspace_access_type_result_t
addrspace_access_type_raw_cast_safe(uint32_t val);

#define addrspace_access_type_cast_safe(val)                                   \
	addrspace_access_type_raw_cast_safe((uint32_t)(val))

bool
addrspace_access_type_raw_is_valid(uint32_t val);

#define addrspace_access_type_is_valid(val)                                    \
	addrspace_access_type_raw_is_valid((uint32_t)(val))

void
vgic_gicr_attach_flags_set_last_valid(vgic_gicr_attach_flags_t *bit_field,
				      bool			val);

bool
vgic_gicr_attach_flags_get_last_valid(const vgic_gicr_attach_flags_t *bit_field);

void
vgic_gicr_attach_flags_copy_last_valid(
	vgic_gicr_attach_flags_t       *bit_field_dst,
	const vgic_gicr_attach_flags_t *bit_field_src);

void
vgic_gicr_attach_flags_set_last(vgic_gicr_attach_flags_t *bit_field, bool val);

bool
vgic_gicr_attach_flags_get_last(const vgic_gicr_attach_flags_t *bit_field);

void
vgic_gicr_attach_flags_copy_last(vgic_gicr_attach_flags_t	*bit_field_dst,
				 const vgic_gicr_attach_flags_t *bit_field_src);

void
addrspace_info_area_entry_data_info_set_size(
	addrspace_info_area_entry_data_info_t *bit_field, size_t val);

size_t
addrspace_info_area_entry_data_info_get_size(
	const addrspace_info_area_entry_data_info_t *bit_field);

void
addrspace_info_area_entry_data_info_copy_size(
	addrspace_info_area_entry_data_info_t	    *bit_field_dst,
	const addrspace_info_area_entry_data_info_t *bit_field_src);

void
addrspace_info_area_entry_data_info_set_alignment(
	addrspace_info_area_entry_data_info_t *bit_field, size_t val);

size_t
addrspace_info_area_entry_data_info_get_alignment(
	const addrspace_info_area_entry_data_info_t *bit_field);

void
addrspace_info_area_entry_data_info_copy_alignment(
	addrspace_info_area_entry_data_info_t	    *bit_field_dst,
	const addrspace_info_area_entry_data_info_t *bit_field_src);

void
addrspace_info_area_entry_flags_set_valid(
	addrspace_info_area_entry_flags_t *bit_field, bool val);

bool
addrspace_info_area_entry_flags_get_valid(
	const addrspace_info_area_entry_flags_t *bit_field);

void
addrspace_info_area_entry_flags_copy_valid(
	addrspace_info_area_entry_flags_t	*bit_field_dst,
	const addrspace_info_area_entry_flags_t *bit_field_src);

addrspace_info_area_id_owner_t
addrspace_info_area_id_owner_raw_cast(uint32_t val);

#define addrspace_info_area_id_owner_cast(val)                                 \
	addrspace_info_area_id_owner_raw_cast((uint32_t)(val))

addrspace_info_area_id_owner_result_t
addrspace_info_area_id_owner_raw_cast_safe(uint32_t val);

#define addrspace_info_area_id_owner_cast_safe(val)                            \
	addrspace_info_area_id_owner_raw_cast_safe((uint32_t)(val))

bool
addrspace_info_area_id_owner_raw_is_valid(uint32_t val);

#define addrspace_info_area_id_owner_is_valid(val)                             \
	addrspace_info_area_id_owner_raw_is_valid((uint32_t)(val))

void
addrspace_info_area_entry_type_set_id(
	addrspace_info_area_entry_type_t *bit_field, uint32_t val);

uint32_t
addrspace_info_area_entry_type_get_id(
	const addrspace_info_area_entry_type_t *bit_field);

void
addrspace_info_area_entry_type_copy_id(
	addrspace_info_area_entry_type_t       *bit_field_dst,
	const addrspace_info_area_entry_type_t *bit_field_src);

void
addrspace_info_area_entry_type_set_owner(
	addrspace_info_area_entry_type_t *bit_field,
	addrspace_info_area_id_owner_t	  val);

addrspace_info_area_id_owner_t
addrspace_info_area_entry_type_get_owner(
	const addrspace_info_area_entry_type_t *bit_field);

void
addrspace_info_area_entry_type_copy_owner(
	addrspace_info_area_entry_type_t       *bit_field_dst,
	const addrspace_info_area_entry_type_t *bit_field_src);

void
addrspace_map_flags_set_partial(addrspace_map_flags_t *bit_field, bool val);

bool
addrspace_map_flags_get_partial(const addrspace_map_flags_t *bit_field);

void
addrspace_map_flags_copy_partial(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src);

void
addrspace_map_flags_set_private(addrspace_map_flags_t *bit_field, bool val);

bool
addrspace_map_flags_get_private(const addrspace_map_flags_t *bit_field);

void
addrspace_map_flags_copy_private(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src);

void
addrspace_map_flags_set_vmmio(addrspace_map_flags_t *bit_field, bool val);

bool
addrspace_map_flags_get_vmmio(const addrspace_map_flags_t *bit_field);

void
addrspace_map_flags_copy_vmmio(addrspace_map_flags_t	   *bit_field_dst,
			       const addrspace_map_flags_t *bit_field_src);

void
addrspace_map_flags_set_whole_extent(addrspace_map_flags_t *bit_field,
				     bool		    val);

bool
addrspace_map_flags_get_whole_extent(const addrspace_map_flags_t *bit_field);

void
addrspace_map_flags_copy_whole_extent(
	addrspace_map_flags_t	    *bit_field_dst,
	const addrspace_map_flags_t *bit_field_src);

void
addrspace_map_flags_set_no_sync(addrspace_map_flags_t *bit_field, bool val);

bool
addrspace_map_flags_get_no_sync(const addrspace_map_flags_t *bit_field);

void
addrspace_map_flags_copy_no_sync(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src);

void
addrspace_modify_pages_flags_set_unlock(
	addrspace_modify_pages_flags_t *bit_field, bool val);

bool
addrspace_modify_pages_flags_get_unlock(
	const addrspace_modify_pages_flags_t *bit_field);

void
addrspace_modify_pages_flags_copy_unlock(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src);

void
addrspace_modify_pages_flags_set_no_sync_unlock(
	addrspace_modify_pages_flags_t *bit_field, bool val);

bool
addrspace_modify_pages_flags_get_no_sync_unlock(
	const addrspace_modify_pages_flags_t *bit_field);

void
addrspace_modify_pages_flags_copy_no_sync_unlock(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src);

void
addrspace_modify_pages_flags_set_do_not_sanitise(
	addrspace_modify_pages_flags_t *bit_field, bool val);

bool
addrspace_modify_pages_flags_get_do_not_sanitise(
	const addrspace_modify_pages_flags_t *bit_field);

void
addrspace_modify_pages_flags_copy_do_not_sanitise(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src);

addrspace_range_configure_op_t
addrspace_range_configure_op_raw_cast(uint32_t val);

#define addrspace_range_configure_op_cast(val)                                 \
	addrspace_range_configure_op_raw_cast((uint32_t)(val))

addrspace_range_configure_op_result_t
addrspace_range_configure_op_raw_cast_safe(uint32_t val);

#define addrspace_range_configure_op_cast_safe(val)                            \
	addrspace_range_configure_op_raw_cast_safe((uint32_t)(val))

bool
addrspace_range_configure_op_raw_is_valid(uint32_t val);

#define addrspace_range_configure_op_is_valid(val)                             \
	addrspace_range_configure_op_raw_is_valid((uint32_t)(val))

addrspace_resume_action_t
addrspace_resume_action_raw_cast(uint32_t val);

#define addrspace_resume_action_cast(val)                                      \
	addrspace_resume_action_raw_cast((uint32_t)(val))

addrspace_resume_action_result_t
addrspace_resume_action_raw_cast_safe(uint32_t val);

#define addrspace_resume_action_cast_safe(val)                                 \
	addrspace_resume_action_raw_cast_safe((uint32_t)(val))

bool
addrspace_resume_action_raw_is_valid(uint32_t val);

#define addrspace_resume_action_is_valid(val)                                  \
	addrspace_resume_action_raw_is_valid((uint32_t)(val))

allocator_memtype_t
allocator_memtype_raw_cast(uint32_t val);

#define allocator_memtype_cast(val) allocator_memtype_raw_cast((uint32_t)(val))

allocator_memtype_result_t
allocator_memtype_raw_cast_safe(uint32_t val);

#define allocator_memtype_cast_safe(val)                                       \
	allocator_memtype_raw_cast_safe((uint32_t)(val))

bool
allocator_memtype_raw_is_valid(uint32_t val);

#define allocator_memtype_is_valid(val)                                        \
	allocator_memtype_raw_is_valid((uint32_t)(val))

void
allocator_memattr_set_type(allocator_memattr_t *bit_field,
			   allocator_memtype_t	val);

allocator_memtype_t
allocator_memattr_get_type(const allocator_memattr_t *bit_field);

void
allocator_memattr_copy_type(allocator_memattr_t	      *bit_field_dst,
			    const allocator_memattr_t *bit_field_src);

uint8_t
allocator_stats_info_get_version(const allocator_stats_info_t *bit_field);

void
cap_rights_addrspace_set_attach(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_attach(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_attach(cap_rights_addrspace_t	      *bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_map(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_map(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_map(cap_rights_addrspace_t	   *bit_field_dst,
			      const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_lookup(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_lookup(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_lookup(cap_rights_addrspace_t	      *bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_configure_range(cap_rights_addrspace_t *bit_field,
					 bool			 val);

bool
cap_rights_addrspace_get_configure_range(
	const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_configure_range(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_map_protected(cap_rights_addrspace_t *bit_field,
				       bool		       val);

bool
cap_rights_addrspace_get_map_protected(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_map_protected(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_modify_protected(cap_rights_addrspace_t *bit_field,
					  bool			  val);

bool
cap_rights_addrspace_get_modify_protected(
	const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_modify_protected(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_add_info(cap_rights_addrspace_t *bit_field, bool val);

bool
cap_rights_addrspace_get_add_info(const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_add_info(cap_rights_addrspace_t	*bit_field_dst,
				   const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_addrspace_set_object_activate(cap_rights_addrspace_t *bit_field,
					 bool			 val);

bool
cap_rights_addrspace_get_object_activate(
	const cap_rights_addrspace_t *bit_field);

void
cap_rights_addrspace_copy_object_activate(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_create(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_create(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_create(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_delete(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_delete(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_delete(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_copy(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_copy(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_copy(cap_rights_cspace_t	  *bit_field_dst,
				const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_attach(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_attach(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_attach(cap_rights_cspace_t	*bit_field_dst,
			      const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_cap_revoke(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_cap_revoke(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_cap_revoke(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src);

void
cap_rights_cspace_set_object_activate(cap_rights_cspace_t *bit_field, bool val);

bool
cap_rights_cspace_get_object_activate(const cap_rights_cspace_t *bit_field);

void
cap_rights_cspace_copy_object_activate(cap_rights_cspace_t *bit_field_dst,
				       const cap_rights_cspace_t *bit_field_src);

void
cap_rights_doorbell_set_send(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_send(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_send(cap_rights_doorbell_t	  *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_receive(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_receive(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_receive(cap_rights_doorbell_t	     *bit_field_dst,
				 const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_bind(cap_rights_doorbell_t *bit_field, bool val);

bool
cap_rights_doorbell_get_bind(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_bind(cap_rights_doorbell_t	  *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_doorbell_set_object_activate(cap_rights_doorbell_t *bit_field,
					bool		       val);

bool
cap_rights_doorbell_get_object_activate(const cap_rights_doorbell_t *bit_field);

void
cap_rights_doorbell_copy_object_activate(
	cap_rights_doorbell_t	    *bit_field_dst,
	const cap_rights_doorbell_t *bit_field_src);

void
cap_rights_generic_set_object_activate(cap_rights_generic_t *bit_field,
				       bool		     val);

bool
cap_rights_generic_get_object_activate(const cap_rights_generic_t *bit_field);

void
cap_rights_generic_copy_object_activate(
	cap_rights_generic_t	   *bit_field_dst,
	const cap_rights_generic_t *bit_field_src);

void
cap_rights_gicv3_its_set_bind_device(cap_rights_gicv3_its_t *bit_field,
				     bool		     val);

bool
cap_rights_gicv3_its_get_bind_device(const cap_rights_gicv3_its_t *bit_field);

void
cap_rights_gicv3_its_copy_bind_device(
	cap_rights_gicv3_its_t	     *bit_field_dst,
	const cap_rights_gicv3_its_t *bit_field_src);

void
cap_rights_gicv3_its_set_object_activate(cap_rights_gicv3_its_t *bit_field,
					 bool			 val);

bool
cap_rights_gicv3_its_get_object_activate(
	const cap_rights_gicv3_its_t *bit_field);

void
cap_rights_gicv3_its_copy_object_activate(
	cap_rights_gicv3_its_t	     *bit_field_dst,
	const cap_rights_gicv3_its_t *bit_field_src);

void
cap_rights_hwirq_set_bind_vic(cap_rights_hwirq_t *bit_field, bool val);

bool
cap_rights_hwirq_get_bind_vic(const cap_rights_hwirq_t *bit_field);

void
cap_rights_hwirq_copy_bind_vic(cap_rights_hwirq_t	*bit_field_dst,
			       const cap_rights_hwirq_t *bit_field_src);

void
cap_rights_hwirq_set_object_activate(cap_rights_hwirq_t *bit_field, bool val);

bool
cap_rights_hwirq_get_object_activate(const cap_rights_hwirq_t *bit_field);

void
cap_rights_hwirq_copy_object_activate(cap_rights_hwirq_t       *bit_field_dst,
				      const cap_rights_hwirq_t *bit_field_src);

void
cap_rights_memextent_set_map(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_map(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_map(cap_rights_memextent_t	   *bit_field_dst,
			      const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_derive(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_derive(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_derive(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_attach(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_attach(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_attach(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_lookup(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_lookup(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_lookup(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_donate(cap_rights_memextent_t *bit_field, bool val);

bool
cap_rights_memextent_get_donate(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_donate(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_protected_host(cap_rights_memextent_t *bit_field,
					bool			val);

bool
cap_rights_memextent_get_protected_host(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_protected_host(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_protected_guest(cap_rights_memextent_t *bit_field,
					 bool			 val);

bool
cap_rights_memextent_get_protected_guest(
	const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_protected_guest(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_map_private(cap_rights_memextent_t *bit_field,
				     bool		     val);

bool
cap_rights_memextent_get_map_private(const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_map_private(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src);

void
cap_rights_memextent_set_object_activate(cap_rights_memextent_t *bit_field,
					 bool			 val);

bool
cap_rights_memextent_get_object_activate(
	const cap_rights_memextent_t *bit_field);

void
cap_rights_memextent_copy_object_activate(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src);

void
cap_rights_msgqueue_set_send(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_send(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_send(cap_rights_msgqueue_t	  *bit_field_dst,
			      const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_receive(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_receive(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_receive(cap_rights_msgqueue_t	     *bit_field_dst,
				 const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_bind_send(cap_rights_msgqueue_t *bit_field, bool val);

bool
cap_rights_msgqueue_get_bind_send(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_bind_send(cap_rights_msgqueue_t       *bit_field_dst,
				   const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_bind_receive(cap_rights_msgqueue_t *bit_field,
				     bool		    val);

bool
cap_rights_msgqueue_get_bind_receive(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_bind_receive(
	cap_rights_msgqueue_t	    *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_msgqueue_set_object_activate(cap_rights_msgqueue_t *bit_field,
					bool		       val);

bool
cap_rights_msgqueue_get_object_activate(const cap_rights_msgqueue_t *bit_field);

void
cap_rights_msgqueue_copy_object_activate(
	cap_rights_msgqueue_t	    *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src);

void
cap_rights_partition_set_object_create(cap_rights_partition_t *bit_field,
				       bool		       val);

bool
cap_rights_partition_get_object_create(const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_object_create(
	cap_rights_partition_t	     *bit_field_dst,
	const cap_rights_partition_t *bit_field_src);

void
cap_rights_partition_set_donate(cap_rights_partition_t *bit_field, bool val);

bool
cap_rights_partition_get_donate(const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_donate(cap_rights_partition_t	      *bit_field_dst,
				 const cap_rights_partition_t *bit_field_src);

void
cap_rights_partition_set_query(cap_rights_partition_t *bit_field, bool val);

bool
cap_rights_partition_get_query(const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_query(cap_rights_partition_t	     *bit_field_dst,
				const cap_rights_partition_t *bit_field_src);

void
cap_rights_partition_set_object_activate(cap_rights_partition_t *bit_field,
					 bool			 val);

bool
cap_rights_partition_get_object_activate(
	const cap_rights_partition_t *bit_field);

void
cap_rights_partition_copy_object_activate(
	cap_rights_partition_t	     *bit_field_dst,
	const cap_rights_partition_t *bit_field_src);

void
cap_rights_pci_function_set_passthrough(cap_rights_pci_function_t *bit_field,
					bool			   val);

bool
cap_rights_pci_function_get_passthrough(
	const cap_rights_pci_function_t *bit_field);

void
cap_rights_pci_function_copy_passthrough(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src);

void
cap_rights_pci_function_set_attach(cap_rights_pci_function_t *bit_field,
				   bool			      val);

bool
cap_rights_pci_function_get_attach(const cap_rights_pci_function_t *bit_field);

void
cap_rights_pci_function_copy_attach(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src);

void
cap_rights_pci_function_set_object_activate(
	cap_rights_pci_function_t *bit_field, bool val);

bool
cap_rights_pci_function_get_object_activate(
	const cap_rights_pci_function_t *bit_field);

void
cap_rights_pci_function_copy_object_activate(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src);

void
cap_rights_pci_host_set_create_function(cap_rights_pci_host_t *bit_field,
					bool		       val);

bool
cap_rights_pci_host_get_create_function(const cap_rights_pci_host_t *bit_field);

void
cap_rights_pci_host_copy_create_function(
	cap_rights_pci_host_t	    *bit_field_dst,
	const cap_rights_pci_host_t *bit_field_src);

void
cap_rights_pci_host_set_set_lockdown(cap_rights_pci_host_t *bit_field,
				     bool		    val);

bool
cap_rights_pci_host_get_set_lockdown(const cap_rights_pci_host_t *bit_field);

void
cap_rights_pci_host_copy_set_lockdown(
	cap_rights_pci_host_t	    *bit_field_dst,
	const cap_rights_pci_host_t *bit_field_src);

void
cap_rights_pci_host_set_object_activate(cap_rights_pci_host_t *bit_field,
					bool		       val);

bool
cap_rights_pci_host_get_object_activate(const cap_rights_pci_host_t *bit_field);

void
cap_rights_pci_host_copy_object_activate(
	cap_rights_pci_host_t	    *bit_field_dst,
	const cap_rights_pci_host_t *bit_field_src);

void
cap_rights_power_set_system_suspend(cap_rights_power_t *bit_field, bool val);

bool
cap_rights_power_get_system_suspend(const cap_rights_power_t *bit_field);

void
cap_rights_power_copy_system_suspend(cap_rights_power_t	      *bit_field_dst,
				     const cap_rights_power_t *bit_field_src);

void
cap_rights_power_set_cpu_suspend(cap_rights_power_t *bit_field, bool val);

bool
cap_rights_power_get_cpu_suspend(const cap_rights_power_t *bit_field);

void
cap_rights_power_copy_cpu_suspend(cap_rights_power_t	   *bit_field_dst,
				  const cap_rights_power_t *bit_field_src);

void
cap_rights_power_set_object_activate(cap_rights_power_t *bit_field, bool val);

bool
cap_rights_power_get_object_activate(const cap_rights_power_t *bit_field);

void
cap_rights_power_copy_object_activate(cap_rights_power_t       *bit_field_dst,
				      const cap_rights_power_t *bit_field_src);

void
cap_rights_smmuv3_set_configure(cap_rights_smmuv3_t *bit_field, bool val);

bool
cap_rights_smmuv3_get_configure(const cap_rights_smmuv3_t *bit_field);

void
cap_rights_smmuv3_copy_configure(cap_rights_smmuv3_t	   *bit_field_dst,
				 const cap_rights_smmuv3_t *bit_field_src);

void
cap_rights_smmuv3_set_manage_streams(cap_rights_smmuv3_t *bit_field, bool val);

bool
cap_rights_smmuv3_get_manage_streams(const cap_rights_smmuv3_t *bit_field);

void
cap_rights_smmuv3_copy_manage_streams(cap_rights_smmuv3_t	*bit_field_dst,
				      const cap_rights_smmuv3_t *bit_field_src);

void
cap_rights_smmuv3_set_object_activate(cap_rights_smmuv3_t *bit_field, bool val);

bool
cap_rights_smmuv3_get_object_activate(const cap_rights_smmuv3_t *bit_field);

void
cap_rights_smmuv3_copy_object_activate(cap_rights_smmuv3_t *bit_field_dst,
				       const cap_rights_smmuv3_t *bit_field_src);

void
cap_rights_thread_set_power(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_power(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_power(cap_rights_thread_t       *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_affinity(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_affinity(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_affinity(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_priority(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_priority(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_priority(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_timeslice(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_timeslice(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_timeslice(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_yield_to(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_yield_to(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_yield_to(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_bind_virq(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_bind_virq(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_bind_virq(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_state(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_state(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_state(cap_rights_thread_t       *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_lifecycle(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_lifecycle(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_lifecycle(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_write_context(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_write_context(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_write_context(cap_rights_thread_t       *bit_field_dst,
				     const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_disable(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_disable(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_disable(cap_rights_thread_t	 *bit_field_dst,
			       const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_bind_local_virq(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_bind_local_virq(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_bind_local_virq(cap_rights_thread_t *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src);

void
cap_rights_thread_set_object_activate(cap_rights_thread_t *bit_field, bool val);

bool
cap_rights_thread_get_object_activate(const cap_rights_thread_t *bit_field);

void
cap_rights_thread_copy_object_activate(cap_rights_thread_t *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src);

void
cap_rights_vgic_its_set_bind_vic(cap_rights_vgic_its_t *bit_field, bool val);

bool
cap_rights_vgic_its_get_bind_vic(const cap_rights_vgic_its_t *bit_field);

void
cap_rights_vgic_its_copy_bind_vic(cap_rights_vgic_its_t	      *bit_field_dst,
				  const cap_rights_vgic_its_t *bit_field_src);

void
cap_rights_vgic_its_set_attach_addrspace(cap_rights_vgic_its_t *bit_field,
					 bool			val);

bool
cap_rights_vgic_its_get_attach_addrspace(const cap_rights_vgic_its_t *bit_field);

void
cap_rights_vgic_its_copy_attach_addrspace(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src);

void
cap_rights_vgic_its_set_bind_devices(cap_rights_vgic_its_t *bit_field,
				     bool		    val);

bool
cap_rights_vgic_its_get_bind_devices(const cap_rights_vgic_its_t *bit_field);

void
cap_rights_vgic_its_copy_bind_devices(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src);

void
cap_rights_vgic_its_set_unbind_devices(cap_rights_vgic_its_t *bit_field,
				       bool		      val);

bool
cap_rights_vgic_its_get_unbind_devices(const cap_rights_vgic_its_t *bit_field);

void
cap_rights_vgic_its_copy_unbind_devices(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src);

void
cap_rights_vgic_its_set_object_activate(cap_rights_vgic_its_t *bit_field,
					bool		       val);

bool
cap_rights_vgic_its_get_object_activate(const cap_rights_vgic_its_t *bit_field);

void
cap_rights_vgic_its_copy_object_activate(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src);

void
cap_rights_vic_set_bind_source(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_bind_source(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_bind_source(cap_rights_vic_t       *bit_field_dst,
				const cap_rights_vic_t *bit_field_src);

void
cap_rights_vic_set_attach_vcpu(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_attach_vcpu(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_attach_vcpu(cap_rights_vic_t       *bit_field_dst,
				const cap_rights_vic_t *bit_field_src);

void
cap_rights_vic_set_attach_vdevice(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_attach_vdevice(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_attach_vdevice(cap_rights_vic_t	  *bit_field_dst,
				   const cap_rights_vic_t *bit_field_src);

void
cap_rights_vic_set_object_activate(cap_rights_vic_t *bit_field, bool val);

bool
cap_rights_vic_get_object_activate(const cap_rights_vic_t *bit_field);

void
cap_rights_vic_copy_object_activate(cap_rights_vic_t	   *bit_field_dst,
				    const cap_rights_vic_t *bit_field_src);

void
cap_rights_virtio_backend_set_bind_virq(cap_rights_virtio_backend_t *bit_field,
					bool			     val);

bool
cap_rights_virtio_backend_get_bind_virq(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_bind_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_backend_set_bind_mmio_frontend_virq(
	cap_rights_virtio_backend_t *bit_field, bool val);

bool
cap_rights_virtio_backend_get_bind_mmio_frontend_virq(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_bind_mmio_frontend_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_backend_set_assert_virq(
	cap_rights_virtio_backend_t *bit_field, bool val);

bool
cap_rights_virtio_backend_get_assert_virq(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_assert_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_backend_set_config(cap_rights_virtio_backend_t *bit_field,
				     bool			  val);

bool
cap_rights_virtio_backend_get_config(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_config(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_backend_set_bind_vpci(cap_rights_virtio_backend_t *bit_field,
					bool			     val);

bool
cap_rights_virtio_backend_get_bind_vpci(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_bind_vpci(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_backend_set_object_activate(
	cap_rights_virtio_backend_t *bit_field, bool val);

bool
cap_rights_virtio_backend_get_object_activate(
	const cap_rights_virtio_backend_t *bit_field);

void
cap_rights_virtio_backend_copy_object_activate(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src);

void
cap_rights_virtio_iommu_set_bind_vpci(cap_rights_virtio_iommu_t *bit_field,
				      bool			 val);

bool
cap_rights_virtio_iommu_get_bind_vpci(
	const cap_rights_virtio_iommu_t *bit_field);

void
cap_rights_virtio_iommu_copy_bind_vpci(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src);

void
cap_rights_virtio_iommu_set_manage_streams(cap_rights_virtio_iommu_t *bit_field,
					   bool			      val);

bool
cap_rights_virtio_iommu_get_manage_streams(
	const cap_rights_virtio_iommu_t *bit_field);

void
cap_rights_virtio_iommu_copy_manage_streams(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src);

void
cap_rights_virtio_iommu_set_object_activate(
	cap_rights_virtio_iommu_t *bit_field, bool val);

bool
cap_rights_virtio_iommu_get_object_activate(
	const cap_rights_virtio_iommu_t *bit_field);

void
cap_rights_virtio_iommu_copy_object_activate(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src);

void
cap_rights_vpci_set_attach(cap_rights_vpci_t *bit_field, bool val);

bool
cap_rights_vpci_get_attach(const cap_rights_vpci_t *bit_field);

void
cap_rights_vpci_copy_attach(cap_rights_vpci_t	    *bit_field_dst,
			    const cap_rights_vpci_t *bit_field_src);

void
cap_rights_vpci_set_bind(cap_rights_vpci_t *bit_field, bool val);

bool
cap_rights_vpci_get_bind(const cap_rights_vpci_t *bit_field);

void
cap_rights_vpci_copy_bind(cap_rights_vpci_t	  *bit_field_dst,
			  const cap_rights_vpci_t *bit_field_src);

void
cap_rights_vpci_set_object_activate(cap_rights_vpci_t *bit_field, bool val);

bool
cap_rights_vpci_get_object_activate(const cap_rights_vpci_t *bit_field);

void
cap_rights_vpci_copy_object_activate(cap_rights_vpci_t	     *bit_field_dst,
				     const cap_rights_vpci_t *bit_field_src);

void
cap_rights_vpm_group_set_attach_vcpu(cap_rights_vpm_group_t *bit_field,
				     bool		     val);

bool
cap_rights_vpm_group_get_attach_vcpu(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_attach_vcpu(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_bind_virq(cap_rights_vpm_group_t *bit_field, bool val);

bool
cap_rights_vpm_group_get_bind_virq(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_bind_virq(cap_rights_vpm_group_t *bit_field_dst,
				    const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_query(cap_rights_vpm_group_t *bit_field, bool val);

bool
cap_rights_vpm_group_get_query(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_query(cap_rights_vpm_group_t	     *bit_field_dst,
				const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_wakeup(cap_rights_vpm_group_t *bit_field, bool val);

bool
cap_rights_vpm_group_get_wakeup(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_wakeup(cap_rights_vpm_group_t	      *bit_field_dst,
				 const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_bind_power(cap_rights_vpm_group_t *bit_field,
				    bool		    val);

bool
cap_rights_vpm_group_get_bind_power(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_bind_power(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_set_threshold(cap_rights_vpm_group_t *bit_field,
				       bool		       val);

bool
cap_rights_vpm_group_get_set_threshold(const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_set_threshold(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vpm_group_set_object_activate(cap_rights_vpm_group_t *bit_field,
					 bool			 val);

bool
cap_rights_vpm_group_get_object_activate(
	const cap_rights_vpm_group_t *bit_field);

void
cap_rights_vpm_group_copy_object_activate(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src);

void
cap_rights_vrtc_set_configure(cap_rights_vrtc_t *bit_field, bool val);

bool
cap_rights_vrtc_get_configure(const cap_rights_vrtc_t *bit_field);

void
cap_rights_vrtc_copy_configure(cap_rights_vrtc_t       *bit_field_dst,
			       const cap_rights_vrtc_t *bit_field_src);

void
cap_rights_vrtc_set_attach_addrspace(cap_rights_vrtc_t *bit_field, bool val);

bool
cap_rights_vrtc_get_attach_addrspace(const cap_rights_vrtc_t *bit_field);

void
cap_rights_vrtc_copy_attach_addrspace(cap_rights_vrtc_t	      *bit_field_dst,
				      const cap_rights_vrtc_t *bit_field_src);

void
cap_rights_vrtc_set_set_time_base(cap_rights_vrtc_t *bit_field, bool val);

bool
cap_rights_vrtc_get_set_time_base(const cap_rights_vrtc_t *bit_field);

void
cap_rights_vrtc_copy_set_time_base(cap_rights_vrtc_t	   *bit_field_dst,
				   const cap_rights_vrtc_t *bit_field_src);

void
cap_rights_vrtc_set_object_activate(cap_rights_vrtc_t *bit_field, bool val);

bool
cap_rights_vrtc_get_object_activate(const cap_rights_vrtc_t *bit_field);

void
cap_rights_vrtc_copy_object_activate(cap_rights_vrtc_t	     *bit_field_dst,
				     const cap_rights_vrtc_t *bit_field_src);

void
cap_rights_vsmmuv2_set_manage_streams(cap_rights_vsmmuv2_t *bit_field,
				      bool		    val);

bool
cap_rights_vsmmuv2_get_manage_streams(const cap_rights_vsmmuv2_t *bit_field);

void
cap_rights_vsmmuv2_copy_manage_streams(
	cap_rights_vsmmuv2_t	   *bit_field_dst,
	const cap_rights_vsmmuv2_t *bit_field_src);

void
cap_rights_vsmmuv2_set_attach_addrspace(cap_rights_vsmmuv2_t *bit_field,
					bool		      val);

bool
cap_rights_vsmmuv2_get_attach_addrspace(const cap_rights_vsmmuv2_t *bit_field);

void
cap_rights_vsmmuv2_copy_attach_addrspace(
	cap_rights_vsmmuv2_t	   *bit_field_dst,
	const cap_rights_vsmmuv2_t *bit_field_src);

void
cap_rights_vsmmuv2_set_object_activate(cap_rights_vsmmuv2_t *bit_field,
				       bool		     val);

bool
cap_rights_vsmmuv2_get_object_activate(const cap_rights_vsmmuv2_t *bit_field);

void
cap_rights_vsmmuv2_copy_object_activate(
	cap_rights_vsmmuv2_t	   *bit_field_dst,
	const cap_rights_vsmmuv2_t *bit_field_src);

void
cap_rights_watchdog_set_attach_vcpu(cap_rights_watchdog_t *bit_field, bool val);

bool
cap_rights_watchdog_get_attach_vcpu(const cap_rights_watchdog_t *bit_field);

void
cap_rights_watchdog_copy_attach_vcpu(cap_rights_watchdog_t *bit_field_dst,
				     const cap_rights_watchdog_t *bit_field_src);

void
cap_rights_watchdog_set_bind_virq(cap_rights_watchdog_t *bit_field, bool val);

bool
cap_rights_watchdog_get_bind_virq(const cap_rights_watchdog_t *bit_field);

void
cap_rights_watchdog_copy_bind_virq(cap_rights_watchdog_t       *bit_field_dst,
				   const cap_rights_watchdog_t *bit_field_src);

void
cap_rights_watchdog_set_manage(cap_rights_watchdog_t *bit_field, bool val);

bool
cap_rights_watchdog_get_manage(const cap_rights_watchdog_t *bit_field);

void
cap_rights_watchdog_copy_manage(cap_rights_watchdog_t	    *bit_field_dst,
				const cap_rights_watchdog_t *bit_field_src);

void
cap_rights_watchdog_set_object_activate(cap_rights_watchdog_t *bit_field,
					bool		       val);

bool
cap_rights_watchdog_get_object_activate(const cap_rights_watchdog_t *bit_field);

void
cap_rights_watchdog_copy_object_activate(
	cap_rights_watchdog_t	    *bit_field_dst,
	const cap_rights_watchdog_t *bit_field_src);

error_t
error_raw_cast(int32_t val);

#define error_cast(val) error_raw_cast((int32_t)(val))

error_result_t
error_raw_cast_safe(int32_t val);

#define error_cast_safe(val) error_raw_cast_safe((int32_t)(val))

bool
error_raw_is_valid(int32_t val);

#define error_is_valid(val) error_raw_is_valid((int32_t)(val))

scheduler_variant_t
scheduler_variant_raw_cast(uint32_t val);

#define scheduler_variant_cast(val) scheduler_variant_raw_cast((uint32_t)(val))

scheduler_variant_result_t
scheduler_variant_raw_cast_safe(uint32_t val);

#define scheduler_variant_cast_safe(val)                                       \
	scheduler_variant_raw_cast_safe((uint32_t)(val))

bool
scheduler_variant_raw_is_valid(uint32_t val);

#define scheduler_variant_is_valid(val)                                        \
	scheduler_variant_raw_is_valid((uint32_t)(val))

bool
hyp_api_flags0_get_partition_cspace(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_doorbell(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_msgqueue(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vic(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vpm(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vcpu(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_memextent(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_trace_ctrl(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_watchdog(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_virtio_mmio(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_prng(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vcpu_run(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_trace_profile(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_vpci(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_power(const hyp_api_flags0_t *bit_field);

uint64_t
hyp_api_flags0_get_res0_0(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags0_get_reserved_16(const hyp_api_flags0_t *bit_field);

scheduler_variant_t
hyp_api_flags0_get_scheduler(const hyp_api_flags0_t *bit_field);

bool
hyp_api_flags1_get_arm_v82_sve(const hyp_api_flags1_t *bit_field);

bool
hyp_api_flags1_get_vgic_ext_spis(const hyp_api_flags1_t *bit_field);

bool
hyp_api_flags1_get_vgic_ext_ppis(const hyp_api_flags1_t *bit_field);

uint64_t
hyp_api_flags2_get_res0_0(const hyp_api_flags2_t *bit_field);

hyp_variant_t
hyp_variant_raw_cast(uint32_t val);

#define hyp_variant_cast(val) hyp_variant_raw_cast((uint32_t)(val))

hyp_variant_result_t
hyp_variant_raw_cast_safe(uint32_t val);

#define hyp_variant_cast_safe(val) hyp_variant_raw_cast_safe((uint32_t)(val))

bool
hyp_variant_raw_is_valid(uint32_t val);

#define hyp_variant_is_valid(val) hyp_variant_raw_is_valid((uint32_t)(val))

uint16_t
hyp_api_info_get_api_version(const hyp_api_info_t *bit_field);

bool
hyp_api_info_get_big_endian(const hyp_api_info_t *bit_field);

bool
hyp_api_info_get_is_64bit(const hyp_api_info_t *bit_field);

hyp_variant_t
hyp_api_info_get_variant(const hyp_api_info_t *bit_field);

pgtable_access_t
pgtable_access_raw_cast(uint32_t val);

#define pgtable_access_cast(val) pgtable_access_raw_cast((uint32_t)(val))

pgtable_access_result_t
pgtable_access_raw_cast_safe(uint32_t val);

#define pgtable_access_cast_safe(val)                                          \
	pgtable_access_raw_cast_safe((uint32_t)(val))

bool
pgtable_access_raw_is_valid(uint32_t val);

#define pgtable_access_is_valid(val)                                           \
	pgtable_access_raw_is_valid((uint32_t)(val))

void
memextent_access_attrs_set_user_access(memextent_access_attrs_t *bit_field,
				       pgtable_access_t		 val);

pgtable_access_t
memextent_access_attrs_get_user_access(
	const memextent_access_attrs_t *bit_field);

void
memextent_access_attrs_copy_user_access(
	memextent_access_attrs_t       *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src);

uint64_t
memextent_access_attrs_get_res_0(const memextent_access_attrs_t *bit_field);

void
memextent_access_attrs_set_kernel_access(memextent_access_attrs_t *bit_field,
					 pgtable_access_t	   val);

pgtable_access_t
memextent_access_attrs_get_kernel_access(
	const memextent_access_attrs_t *bit_field);

void
memextent_access_attrs_copy_kernel_access(
	memextent_access_attrs_t       *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src);

memextent_memtype_t
memextent_memtype_raw_cast(uint32_t val);

#define memextent_memtype_cast(val) memextent_memtype_raw_cast((uint32_t)(val))

memextent_memtype_result_t
memextent_memtype_raw_cast_safe(uint32_t val);

#define memextent_memtype_cast_safe(val)                                       \
	memextent_memtype_raw_cast_safe((uint32_t)(val))

bool
memextent_memtype_raw_is_valid(uint32_t val);

#define memextent_memtype_is_valid(val)                                        \
	memextent_memtype_raw_is_valid((uint32_t)(val))

memextent_type_t
memextent_type_raw_cast(uint32_t val);

#define memextent_type_cast(val) memextent_type_raw_cast((uint32_t)(val))

memextent_type_result_t
memextent_type_raw_cast_safe(uint32_t val);

#define memextent_type_cast_safe(val)                                          \
	memextent_type_raw_cast_safe((uint32_t)(val))

bool
memextent_type_raw_is_valid(uint32_t val);

#define memextent_type_is_valid(val)                                           \
	memextent_type_raw_is_valid((uint32_t)(val))

void
memextent_attrs_set_access(memextent_attrs_t *bit_field, pgtable_access_t val);

pgtable_access_t
memextent_attrs_get_access(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_access(memextent_attrs_t	    *bit_field_dst,
			    const memextent_attrs_t *bit_field_src);

uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field);

void
memextent_attrs_set_memtype(memextent_attrs_t  *bit_field,
			    memextent_memtype_t val);

memextent_memtype_t
memextent_attrs_get_memtype(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_memtype(memextent_attrs_t	     *bit_field_dst,
			     const memextent_attrs_t *bit_field_src);

void
memextent_attrs_set_type(memextent_attrs_t *bit_field, memextent_type_t val);

memextent_type_t
memextent_attrs_get_type(const memextent_attrs_t *bit_field);

void
memextent_attrs_copy_type(memextent_attrs_t	  *bit_field_dst,
			  const memextent_attrs_t *bit_field_src);

memextent_donate_type_t
memextent_donate_type_raw_cast(uint32_t val);

#define memextent_donate_type_cast(val)                                        \
	memextent_donate_type_raw_cast((uint32_t)(val))

memextent_donate_type_result_t
memextent_donate_type_raw_cast_safe(uint32_t val);

#define memextent_donate_type_cast_safe(val)                                   \
	memextent_donate_type_raw_cast_safe((uint32_t)(val))

bool
memextent_donate_type_raw_is_valid(uint32_t val);

#define memextent_donate_type_is_valid(val)                                    \
	memextent_donate_type_raw_is_valid((uint32_t)(val))

void
memextent_donate_options_set_type(memextent_donate_options_t *bit_field,
				  memextent_donate_type_t     val);

memextent_donate_type_t
memextent_donate_options_get_type(const memextent_donate_options_t *bit_field);

void
memextent_donate_options_copy_type(
	memextent_donate_options_t	 *bit_field_dst,
	const memextent_donate_options_t *bit_field_src);

uint64_t
memextent_donate_options_get_res_0(const memextent_donate_options_t *bit_field);

void
memextent_donate_options_set_no_sync(memextent_donate_options_t *bit_field,
				     bool			 val);

bool
memextent_donate_options_get_no_sync(
	const memextent_donate_options_t *bit_field);

void
memextent_donate_options_copy_no_sync(
	memextent_donate_options_t	 *bit_field_dst,
	const memextent_donate_options_t *bit_field_src);

pgtable_vm_memtype_t
pgtable_vm_memtype_raw_cast(uint32_t val);

#define pgtable_vm_memtype_cast(val)                                           \
	pgtable_vm_memtype_raw_cast((uint32_t)(val))

pgtable_vm_memtype_result_t
pgtable_vm_memtype_raw_cast_safe(uint32_t val);

#define pgtable_vm_memtype_cast_safe(val)                                      \
	pgtable_vm_memtype_raw_cast_safe((uint32_t)(val))

bool
pgtable_vm_memtype_raw_is_valid(uint32_t val);

#define pgtable_vm_memtype_is_valid(val)                                       \
	pgtable_vm_memtype_raw_is_valid((uint32_t)(val))

void
memextent_mapping_attrs_set_user_access(memextent_mapping_attrs_t *bit_field,
					pgtable_access_t	   val);

pgtable_access_t
memextent_mapping_attrs_get_user_access(
	const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_user_access(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

uint64_t
memextent_mapping_attrs_get_res_0(const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_set_kernel_access(memextent_mapping_attrs_t *bit_field,
					  pgtable_access_t	     val);

pgtable_access_t
memextent_mapping_attrs_get_kernel_access(
	const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_kernel_access(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

void
memextent_mapping_attrs_set_memtype(memextent_mapping_attrs_t *bit_field,
				    pgtable_vm_memtype_t       val);

pgtable_vm_memtype_t
memextent_mapping_attrs_get_memtype(const memextent_mapping_attrs_t *bit_field);

void
memextent_mapping_attrs_copy_memtype(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src);

memextent_modify_op_t
memextent_modify_op_raw_cast(uint32_t val);

#define memextent_modify_op_cast(val)                                          \
	memextent_modify_op_raw_cast((uint32_t)(val))

memextent_modify_op_result_t
memextent_modify_op_raw_cast_safe(uint32_t val);

#define memextent_modify_op_cast_safe(val)                                     \
	memextent_modify_op_raw_cast_safe((uint32_t)(val))

bool
memextent_modify_op_raw_is_valid(uint32_t val);

#define memextent_modify_op_is_valid(val)                                      \
	memextent_modify_op_raw_is_valid((uint32_t)(val))

void
memextent_modify_flags_set_op(memextent_modify_flags_t *bit_field,
			      memextent_modify_op_t	val);

memextent_modify_op_t
memextent_modify_flags_get_op(const memextent_modify_flags_t *bit_field);

void
memextent_modify_flags_copy_op(memextent_modify_flags_t	      *bit_field_dst,
			       const memextent_modify_flags_t *bit_field_src);

uint64_t
memextent_modify_flags_get_res_0(const memextent_modify_flags_t *bit_field);

void
memextent_modify_flags_set_no_sync(memextent_modify_flags_t *bit_field,
				   bool			     val);

bool
memextent_modify_flags_get_no_sync(const memextent_modify_flags_t *bit_field);

void
memextent_modify_flags_copy_no_sync(
	memextent_modify_flags_t       *bit_field_dst,
	const memextent_modify_flags_t *bit_field_src);

void
msgqueue_create_info_set_queue_depth(msgqueue_create_info_t *bit_field,
				     uint16_t		     val);

uint16_t
msgqueue_create_info_get_queue_depth(const msgqueue_create_info_t *bit_field);

void
msgqueue_create_info_copy_queue_depth(
	msgqueue_create_info_t	     *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src);

void
msgqueue_create_info_set_max_msg_size(msgqueue_create_info_t *bit_field,
				      uint16_t		      val);

uint16_t
msgqueue_create_info_get_max_msg_size(const msgqueue_create_info_t *bit_field);

void
msgqueue_create_info_copy_max_msg_size(
	msgqueue_create_info_t	     *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src);

void
msgqueue_send_flags_set_push(msgqueue_send_flags_t *bit_field, bool val);

bool
msgqueue_send_flags_get_push(const msgqueue_send_flags_t *bit_field);

void
msgqueue_send_flags_copy_push(msgqueue_send_flags_t	  *bit_field_dst,
			      const msgqueue_send_flags_t *bit_field_src);

partition_donate_type_t
partition_donate_type_raw_cast(uint32_t val);

#define partition_donate_type_cast(val)                                        \
	partition_donate_type_raw_cast((uint32_t)(val))

partition_donate_type_result_t
partition_donate_type_raw_cast_safe(uint32_t val);

#define partition_donate_type_cast_safe(val)                                   \
	partition_donate_type_raw_cast_safe((uint32_t)(val))

bool
partition_donate_type_raw_is_valid(uint32_t val);

#define partition_donate_type_is_valid(val)                                    \
	partition_donate_type_raw_is_valid((uint32_t)(val))

void
partition_donate_flags_set_type(partition_donate_flags_t *bit_field,
				partition_donate_type_t	  val);

partition_donate_type_t
partition_donate_flags_get_type(const partition_donate_flags_t *bit_field);

void
partition_donate_flags_copy_type(partition_donate_flags_t	*bit_field_dst,
				 const partition_donate_flags_t *bit_field_src);

uint32_t
partition_donate_flags_get_res0(const partition_donate_flags_t *bit_field);

partition_query_type_t
partition_query_type_raw_cast(uint32_t val);

#define partition_query_type_cast(val)                                         \
	partition_query_type_raw_cast((uint32_t)(val))

partition_query_type_result_t
partition_query_type_raw_cast_safe(uint32_t val);

#define partition_query_type_cast_safe(val)                                    \
	partition_query_type_raw_cast_safe((uint32_t)(val))

bool
partition_query_type_raw_is_valid(uint32_t val);

#define partition_query_type_is_valid(val)                                     \
	partition_query_type_raw_is_valid((uint32_t)(val))

void
partition_query_flags_set_type(partition_query_flags_t *bit_field,
			       partition_query_type_t	val);

partition_query_type_t
partition_query_flags_get_type(const partition_query_flags_t *bit_field);

void
partition_query_flags_copy_type(partition_query_flags_t	      *bit_field_dst,
				const partition_query_flags_t *bit_field_src);

uint32_t
partition_query_flags_get_res0(const partition_query_flags_t *bit_field);

void
pci_capability_access_flags_set_passthrough_visible(
	pci_capability_access_flags_t *bit_field, bool val);

bool
pci_capability_access_flags_get_passthrough_visible(
	const pci_capability_access_flags_t *bit_field);

void
pci_capability_access_flags_copy_passthrough_visible(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src);

void
pci_capability_access_flags_set_passthrough_writable(
	pci_capability_access_flags_t *bit_field, bool val);

bool
pci_capability_access_flags_get_passthrough_writable(
	const pci_capability_access_flags_t *bit_field);

void
pci_capability_access_flags_copy_passthrough_writable(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src);

void
pci_capability_access_flags_set_lockdown_visible(
	pci_capability_access_flags_t *bit_field, bool val);

bool
pci_capability_access_flags_get_lockdown_visible(
	const pci_capability_access_flags_t *bit_field);

void
pci_capability_access_flags_copy_lockdown_visible(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src);

void
pci_capability_access_flags_set_lockdown_writable(
	pci_capability_access_flags_t *bit_field, bool val);

bool
pci_capability_access_flags_get_lockdown_writable(
	const pci_capability_access_flags_t *bit_field);

void
pci_capability_access_flags_copy_lockdown_writable(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src);

void
pci_function_option_flags_set_passthrough(
	pci_function_option_flags_t *bit_field, bool val);

bool
pci_function_option_flags_get_passthrough(
	const pci_function_option_flags_t *bit_field);

void
pci_function_option_flags_copy_passthrough(
	pci_function_option_flags_t	  *bit_field_dst,
	const pci_function_option_flags_t *bit_field_src);

void
pci_function_option_flags_set_sr_iov_vf(pci_function_option_flags_t *bit_field,
					bool			     val);

bool
pci_function_option_flags_get_sr_iov_vf(
	const pci_function_option_flags_t *bit_field);

void
pci_function_option_flags_copy_sr_iov_vf(
	pci_function_option_flags_t	  *bit_field_dst,
	const pci_function_option_flags_t *bit_field_src);

pci_host_lockdown_state_t
pci_host_lockdown_state_raw_cast(uint32_t val);

#define pci_host_lockdown_state_cast(val)                                      \
	pci_host_lockdown_state_raw_cast((uint32_t)(val))

pci_host_lockdown_state_result_t
pci_host_lockdown_state_raw_cast_safe(uint32_t val);

#define pci_host_lockdown_state_cast_safe(val)                                 \
	pci_host_lockdown_state_raw_cast_safe((uint32_t)(val))

bool
pci_host_lockdown_state_raw_is_valid(uint32_t val);

#define pci_host_lockdown_state_is_valid(val)                                  \
	pci_host_lockdown_state_raw_is_valid((uint32_t)(val))

void
pci_host_option_flags_set_pcie(pci_host_option_flags_t *bit_field, bool val);

bool
pci_host_option_flags_get_pcie(const pci_host_option_flags_t *bit_field);

void
pci_host_option_flags_copy_pcie(pci_host_option_flags_t	      *bit_field_dst,
				const pci_host_option_flags_t *bit_field_src);

void
pci_host_option_flags_set_lockdown(pci_host_option_flags_t *bit_field,
				   bool			    val);

bool
pci_host_option_flags_get_lockdown(const pci_host_option_flags_t *bit_field);

void
pci_host_option_flags_copy_lockdown(
	pci_host_option_flags_t	      *bit_field_dst,
	const pci_host_option_flags_t *bit_field_src);

void
pci_responder_id_set_function(pci_responder_id_t *bit_field, index_t val);

index_t
pci_responder_id_get_function(const pci_responder_id_t *bit_field);

void
pci_responder_id_copy_function(pci_responder_id_t	*bit_field_dst,
			       const pci_responder_id_t *bit_field_src);

void
pci_responder_id_set_slot(pci_responder_id_t *bit_field, index_t val);

index_t
pci_responder_id_get_slot(const pci_responder_id_t *bit_field);

void
pci_responder_id_copy_slot(pci_responder_id_t	    *bit_field_dst,
			   const pci_responder_id_t *bit_field_src);

void
pci_responder_id_set_bus(pci_responder_id_t *bit_field, index_t val);

index_t
pci_responder_id_get_bus(const pci_responder_id_t *bit_field);

void
pci_responder_id_copy_bus(pci_responder_id_t	   *bit_field_dst,
			  const pci_responder_id_t *bit_field_src);

void
root_env_mmio_range_properties_set_num_pages(
	root_env_mmio_range_properties_t *bit_field, uint32_t val);

uint32_t
root_env_mmio_range_properties_get_num_pages(
	const root_env_mmio_range_properties_t *bit_field);

void
root_env_mmio_range_properties_copy_num_pages(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src);

void
root_env_mmio_range_properties_set_access(
	root_env_mmio_range_properties_t *bit_field, pgtable_access_t val);

pgtable_access_t
root_env_mmio_range_properties_get_access(
	const root_env_mmio_range_properties_t *bit_field);

void
root_env_mmio_range_properties_copy_access(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src);

void
root_env_mmio_range_properties_set_res_s2pt_attr(
	root_env_mmio_range_properties_t *bit_field, uint8_t val);

uint8_t
root_env_mmio_range_properties_get_res_s2pt_attr(
	const root_env_mmio_range_properties_t *bit_field);

void
root_env_mmio_range_properties_copy_res_s2pt_attr(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src);

void
root_env_mmio_range_properties_set_pvm_unmapped(
	root_env_mmio_range_properties_t *bit_field, bool val);

bool
root_env_mmio_range_properties_get_pvm_unmapped(
	const root_env_mmio_range_properties_t *bit_field);

void
root_env_mmio_range_properties_copy_pvm_unmapped(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src);

void
root_env_mmio_range_properties_set_non_exclusive(
	root_env_mmio_range_properties_t *bit_field, bool val);

bool
root_env_mmio_range_properties_get_non_exclusive(
	const root_env_mmio_range_properties_t *bit_field);

void
root_env_mmio_range_properties_copy_non_exclusive(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src);

scheduler_yield_hint_t
scheduler_yield_hint_raw_cast(uint32_t val);

#define scheduler_yield_hint_cast(val)                                         \
	scheduler_yield_hint_raw_cast((uint32_t)(val))

scheduler_yield_hint_result_t
scheduler_yield_hint_raw_cast_safe(uint32_t val);

#define scheduler_yield_hint_cast_safe(val)                                    \
	scheduler_yield_hint_raw_cast_safe((uint32_t)(val))

bool
scheduler_yield_hint_raw_is_valid(uint32_t val);

#define scheduler_yield_hint_is_valid(val)                                     \
	scheduler_yield_hint_raw_is_valid((uint32_t)(val))

void
scheduler_yield_control_set_hint(scheduler_yield_control_t *bit_field,
				 scheduler_yield_hint_t	    val);

scheduler_yield_hint_t
scheduler_yield_control_get_hint(const scheduler_yield_control_t *bit_field);

void
scheduler_yield_control_copy_hint(
	scheduler_yield_control_t	*bit_field_dst,
	const scheduler_yield_control_t *bit_field_src);

void
scheduler_yield_control_set_impl_def(scheduler_yield_control_t *bit_field,
				     bool			val);

bool
scheduler_yield_control_get_impl_def(const scheduler_yield_control_t *bit_field);

void
scheduler_yield_control_copy_impl_def(
	scheduler_yield_control_t	*bit_field_dst,
	const scheduler_yield_control_t *bit_field_src);

sdei_error_reason_t
sdei_error_reason_raw_cast(uint32_t val);

#define sdei_error_reason_cast(val) sdei_error_reason_raw_cast((uint32_t)(val))

sdei_error_reason_result_t
sdei_error_reason_raw_cast_safe(uint32_t val);

#define sdei_error_reason_cast_safe(val)                                       \
	sdei_error_reason_raw_cast_safe((uint32_t)(val))

bool
sdei_error_reason_raw_is_valid(uint32_t val);

#define sdei_error_reason_is_valid(val)                                        \
	sdei_error_reason_raw_is_valid((uint32_t)(val))

void
sdei_error_flags_set_reason(sdei_error_flags_t *bit_field,
			    sdei_error_reason_t val);

sdei_error_reason_t
sdei_error_flags_get_reason(const sdei_error_flags_t *bit_field);

void
sdei_error_flags_copy_reason(sdei_error_flags_t	      *bit_field_dst,
			     const sdei_error_flags_t *bit_field_src);

uint32_t
sdei_error_flags_get_res0(const sdei_error_flags_t *bit_field);

void
sdei_error_flags_set_system_error(sdei_error_flags_t *bit_field, bool val);

bool
sdei_error_flags_get_system_error(const sdei_error_flags_t *bit_field);

void
sdei_error_flags_copy_system_error(sdei_error_flags_t	    *bit_field_dst,
				   const sdei_error_flags_t *bit_field_src);

smccc_arch_function_t
smccc_arch_function_raw_cast(uint32_t val);

#define smccc_arch_function_cast(val)                                          \
	smccc_arch_function_raw_cast((uint32_t)(val))

smccc_arch_function_result_t
smccc_arch_function_raw_cast_safe(uint32_t val);

#define smccc_arch_function_cast_safe(val)                                     \
	smccc_arch_function_raw_cast_safe((uint32_t)(val))

bool
smccc_arch_function_raw_is_valid(uint32_t val);

#define smccc_arch_function_is_valid(val)                                      \
	smccc_arch_function_raw_is_valid((uint32_t)(val))

smccc_owner_id_t
smccc_owner_id_raw_cast(uint32_t val);

#define smccc_owner_id_cast(val) smccc_owner_id_raw_cast((uint32_t)(val))

smccc_owner_id_result_t
smccc_owner_id_raw_cast_safe(uint32_t val);

#define smccc_owner_id_cast_safe(val)                                          \
	smccc_owner_id_raw_cast_safe((uint32_t)(val))

bool
smccc_owner_id_raw_is_valid(uint32_t val);

#define smccc_owner_id_is_valid(val)                                           \
	smccc_owner_id_raw_is_valid((uint32_t)(val))

void
smccc_function_id_set_function(smccc_function_id_t *bit_field,
			       smccc_function_t	    val);

smccc_function_t
smccc_function_id_get_function(const smccc_function_id_t *bit_field);

void
smccc_function_id_copy_function(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src);

void
smccc_function_id_set_sve_live_state_hint(smccc_function_id_t *bit_field,
					  bool		       val);

bool
smccc_function_id_get_sve_live_state_hint(const smccc_function_id_t *bit_field);

void
smccc_function_id_copy_sve_live_state_hint(
	smccc_function_id_t	  *bit_field_dst,
	const smccc_function_id_t *bit_field_src);

uint32_t
smccc_function_id_get_res0(const smccc_function_id_t *bit_field);

void
smccc_function_id_set_owner_id(smccc_function_id_t *bit_field,
			       smccc_owner_id_t	    val);

smccc_owner_id_t
smccc_function_id_get_owner_id(const smccc_function_id_t *bit_field);

void
smccc_function_id_copy_owner_id(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src);

void
smccc_function_id_set_is_smc64(smccc_function_id_t *bit_field, bool val);

bool
smccc_function_id_get_is_smc64(const smccc_function_id_t *bit_field);

void
smccc_function_id_copy_is_smc64(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src);

void
smccc_function_id_set_is_fast(smccc_function_id_t *bit_field, bool val);

bool
smccc_function_id_get_is_fast(const smccc_function_id_t *bit_field);

void
smccc_function_id_copy_is_fast(smccc_function_id_t	 *bit_field_dst,
			       const smccc_function_id_t *bit_field_src);

smccc_standard_hyp_function_t
smccc_standard_hyp_function_raw_cast(uint32_t val);

#define smccc_standard_hyp_function_cast(val)                                  \
	smccc_standard_hyp_function_raw_cast((uint32_t)(val))

smccc_standard_hyp_function_result_t
smccc_standard_hyp_function_raw_cast_safe(uint32_t val);

#define smccc_standard_hyp_function_cast_safe(val)                             \
	smccc_standard_hyp_function_raw_cast_safe((uint32_t)(val))

bool
smccc_standard_hyp_function_raw_is_valid(uint32_t val);

#define smccc_standard_hyp_function_is_valid(val)                              \
	smccc_standard_hyp_function_raw_is_valid((uint32_t)(val))

smccc_vendor_hyp_function_t
smccc_vendor_hyp_function_raw_cast(uint32_t val);

#define smccc_vendor_hyp_function_cast(val)                                    \
	smccc_vendor_hyp_function_raw_cast((uint32_t)(val))

smccc_vendor_hyp_function_result_t
smccc_vendor_hyp_function_raw_cast_safe(uint32_t val);

#define smccc_vendor_hyp_function_cast_safe(val)                               \
	smccc_vendor_hyp_function_raw_cast_safe((uint32_t)(val))

bool
smccc_vendor_hyp_function_raw_is_valid(uint32_t val);

#define smccc_vendor_hyp_function_is_valid(val)                                \
	smccc_vendor_hyp_function_raw_is_valid((uint32_t)(val))

smccc_vendor_hyp_function_class_t
smccc_vendor_hyp_function_class_raw_cast(uint32_t val);

#define smccc_vendor_hyp_function_class_cast(val)                              \
	smccc_vendor_hyp_function_class_raw_cast((uint32_t)(val))

smccc_vendor_hyp_function_class_result_t
smccc_vendor_hyp_function_class_raw_cast_safe(uint32_t val);

#define smccc_vendor_hyp_function_class_cast_safe(val)                         \
	smccc_vendor_hyp_function_class_raw_cast_safe((uint32_t)(val))

bool
smccc_vendor_hyp_function_class_raw_is_valid(uint32_t val);

#define smccc_vendor_hyp_function_class_is_valid(val)                          \
	smccc_vendor_hyp_function_class_raw_is_valid((uint32_t)(val))

void
smccc_vendor_hyp_function_id_set_function(
	smccc_vendor_hyp_function_id_t *bit_field, uint16_t val);

uint16_t
smccc_vendor_hyp_function_id_get_function(
	const smccc_vendor_hyp_function_id_t *bit_field);

void
smccc_vendor_hyp_function_id_copy_function(
	smccc_vendor_hyp_function_id_t	     *bit_field_dst,
	const smccc_vendor_hyp_function_id_t *bit_field_src);

void
smccc_vendor_hyp_function_id_set_call_class(
	smccc_vendor_hyp_function_id_t	 *bit_field,
	smccc_vendor_hyp_function_class_t val);

smccc_vendor_hyp_function_class_t
smccc_vendor_hyp_function_id_get_call_class(
	const smccc_vendor_hyp_function_id_t *bit_field);

void
smccc_vendor_hyp_function_id_copy_call_class(
	smccc_vendor_hyp_function_id_t	     *bit_field_dst,
	const smccc_vendor_hyp_function_id_t *bit_field_src);

trace_class_t
trace_class_raw_cast(uint32_t val);

#define trace_class_cast(val) trace_class_raw_cast((uint32_t)(val))

trace_class_result_t
trace_class_raw_cast_safe(uint32_t val);

#define trace_class_cast_safe(val) trace_class_raw_cast_safe((uint32_t)(val))

bool
trace_class_raw_is_valid(uint32_t val);

#define trace_class_is_valid(val) trace_class_raw_is_valid((uint32_t)(val))

trace_configure_parameter_t
trace_configure_parameter_raw_cast(uint32_t val);

#define trace_configure_parameter_cast(val)                                    \
	trace_configure_parameter_raw_cast((uint32_t)(val))

trace_configure_parameter_result_t
trace_configure_parameter_raw_cast_safe(uint32_t val);

#define trace_configure_parameter_cast_safe(val)                               \
	trace_configure_parameter_raw_cast_safe((uint32_t)(val))

bool
trace_configure_parameter_raw_is_valid(uint32_t val);

#define trace_configure_parameter_is_valid(val)                                \
	trace_configure_parameter_raw_is_valid((uint32_t)(val))

vcpu_affinity_type_t
vcpu_affinity_type_raw_cast(int32_t val);

#define vcpu_affinity_type_cast(val) vcpu_affinity_type_raw_cast((int32_t)(val))

vcpu_affinity_type_result_t
vcpu_affinity_type_raw_cast_safe(int32_t val);

#define vcpu_affinity_type_cast_safe(val)                                      \
	vcpu_affinity_type_raw_cast_safe((int32_t)(val))

bool
vcpu_affinity_type_raw_is_valid(int32_t val);

#define vcpu_affinity_type_is_valid(val)                                       \
	vcpu_affinity_type_raw_is_valid((int32_t)(val))

vcpu_local_virq_type_t
vcpu_local_virq_type_raw_cast(uint32_t val);

#define vcpu_local_virq_type_cast(val)                                         \
	vcpu_local_virq_type_raw_cast((uint32_t)(val))

vcpu_local_virq_type_result_t
vcpu_local_virq_type_raw_cast_safe(uint32_t val);

#define vcpu_local_virq_type_cast_safe(val)                                    \
	vcpu_local_virq_type_raw_cast_safe((uint32_t)(val))

bool
vcpu_local_virq_type_raw_is_valid(uint32_t val);

#define vcpu_local_virq_type_is_valid(val)                                     \
	vcpu_local_virq_type_raw_is_valid((uint32_t)(val))

void
vcpu_option_flags_set_pinned(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_pinned(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_pinned(vcpu_option_flags_t	*bit_field_dst,
			      const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_ras_error_handler(vcpu_option_flags_t *bit_field,
					bool		     val);

bool
vcpu_option_flags_get_ras_error_handler(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_ras_error_handler(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_amu_counting_disabled(vcpu_option_flags_t *bit_field,
					    bool		 val);

bool
vcpu_option_flags_get_amu_counting_disabled(
	const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_amu_counting_disabled(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_sve_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_sve_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_sve_allowed(vcpu_option_flags_t	     *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_debug_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_debug_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_debug_allowed(vcpu_option_flags_t       *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_trace_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_trace_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_trace_allowed(vcpu_option_flags_t       *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_mpam_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_mpam_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_mpam_allowed(vcpu_option_flags_t	      *bit_field_dst,
				    const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_critical(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_critical(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_critical(vcpu_option_flags_t	  *bit_field_dst,
				const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_vcpu_run_scheduled(vcpu_option_flags_t *bit_field,
					 bool		      val);

bool
vcpu_option_flags_get_vcpu_run_scheduled(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_vcpu_run_scheduled(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_sme_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_sme_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_sme_allowed(vcpu_option_flags_t	     *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_sdei_allowed(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_sdei_allowed(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_sdei_allowed(vcpu_option_flags_t	      *bit_field_dst,
				    const vcpu_option_flags_t *bit_field_src);

void
vcpu_option_flags_set_hlos_vm(vcpu_option_flags_t *bit_field, bool val);

bool
vcpu_option_flags_get_hlos_vm(const vcpu_option_flags_t *bit_field);

void
vcpu_option_flags_copy_hlos_vm(vcpu_option_flags_t	 *bit_field_dst,
			       const vcpu_option_flags_t *bit_field_src);

void
vcpu_poweroff_flags_set_last_vcpu(vcpu_poweroff_flags_t *bit_field, bool val);

bool
vcpu_poweroff_flags_get_last_vcpu(const vcpu_poweroff_flags_t *bit_field);

void
vcpu_poweroff_flags_copy_last_vcpu(vcpu_poweroff_flags_t       *bit_field_dst,
				   const vcpu_poweroff_flags_t *bit_field_src);

void
vcpu_poweron_flags_set_preserve_entry_point(vcpu_poweron_flags_t *bit_field,
					    bool		  val);

bool
vcpu_poweron_flags_get_preserve_entry_point(
	const vcpu_poweron_flags_t *bit_field);

void
vcpu_poweron_flags_copy_preserve_entry_point(
	vcpu_poweron_flags_t	   *bit_field_dst,
	const vcpu_poweron_flags_t *bit_field_src);

void
vcpu_poweron_flags_set_preserve_context(vcpu_poweron_flags_t *bit_field,
					bool		      val);

bool
vcpu_poweron_flags_get_preserve_context(const vcpu_poweron_flags_t *bit_field);

void
vcpu_poweron_flags_copy_preserve_context(
	vcpu_poweron_flags_t	   *bit_field_dst,
	const vcpu_poweron_flags_t *bit_field_src);

vcpu_register_set_t
vcpu_register_set_raw_cast(uint32_t val);

#define vcpu_register_set_cast(val) vcpu_register_set_raw_cast((uint32_t)(val))

vcpu_register_set_result_t
vcpu_register_set_raw_cast_safe(uint32_t val);

#define vcpu_register_set_cast_safe(val)                                       \
	vcpu_register_set_raw_cast_safe((uint32_t)(val))

bool
vcpu_register_set_raw_is_valid(uint32_t val);

#define vcpu_register_set_is_valid(val)                                        \
	vcpu_register_set_raw_is_valid((uint32_t)(val))

void
vcpu_run_poweroff_flags_set_exited(vcpu_run_poweroff_flags_t *bit_field,
				   bool			      val);

bool
vcpu_run_poweroff_flags_get_exited(const vcpu_run_poweroff_flags_t *bit_field);

void
vcpu_run_poweroff_flags_copy_exited(
	vcpu_run_poweroff_flags_t	*bit_field_dst,
	const vcpu_run_poweroff_flags_t *bit_field_src);

vcpu_run_state_t
vcpu_run_state_raw_cast(uint32_t val);

#define vcpu_run_state_cast(val) vcpu_run_state_raw_cast((uint32_t)(val))

vcpu_run_state_result_t
vcpu_run_state_raw_cast_safe(uint32_t val);

#define vcpu_run_state_cast_safe(val)                                          \
	vcpu_run_state_raw_cast_safe((uint32_t)(val))

bool
vcpu_run_state_raw_is_valid(uint32_t val);

#define vcpu_run_state_is_valid(val)                                           \
	vcpu_run_state_raw_is_valid((uint32_t)(val))

vcpu_run_wakeup_from_state_t
vcpu_run_wakeup_from_state_raw_cast(uint32_t val);

#define vcpu_run_wakeup_from_state_cast(val)                                   \
	vcpu_run_wakeup_from_state_raw_cast((uint32_t)(val))

vcpu_run_wakeup_from_state_result_t
vcpu_run_wakeup_from_state_raw_cast_safe(uint32_t val);

#define vcpu_run_wakeup_from_state_cast_safe(val)                              \
	vcpu_run_wakeup_from_state_raw_cast_safe((uint32_t)(val))

bool
vcpu_run_wakeup_from_state_raw_is_valid(uint32_t val);

#define vcpu_run_wakeup_from_state_is_valid(val)                               \
	vcpu_run_wakeup_from_state_raw_is_valid((uint32_t)(val))

vcpu_virq_type_t
vcpu_virq_type_raw_cast(uint32_t val);

#define vcpu_virq_type_cast(val) vcpu_virq_type_raw_cast((uint32_t)(val))

vcpu_virq_type_result_t
vcpu_virq_type_raw_cast_safe(uint32_t val);

#define vcpu_virq_type_cast_safe(val)                                          \
	vcpu_virq_type_raw_cast_safe((uint32_t)(val))

bool
vcpu_virq_type_raw_is_valid(uint32_t val);

#define vcpu_virq_type_is_valid(val)                                           \
	vcpu_virq_type_raw_is_valid((uint32_t)(val))

void
vic_msi_source_config_set_index(vic_msi_source_config_t *bit_field,
				uint16_t		 val);

uint16_t
vic_msi_source_config_get_index(const vic_msi_source_config_t *bit_field);

void
vic_msi_source_config_copy_index(vic_msi_source_config_t       *bit_field_dst,
				 const vic_msi_source_config_t *bit_field_src);

uint64_t
vic_msi_source_config_get_res0(const vic_msi_source_config_t *bit_field);

void
vic_option_flags_set_max_msis_valid(vic_option_flags_t *bit_field, bool val);

bool
vic_option_flags_get_max_msis_valid(const vic_option_flags_t *bit_field);

void
vic_option_flags_copy_max_msis_valid(vic_option_flags_t	      *bit_field_dst,
				     const vic_option_flags_t *bit_field_src);

void
vic_option_flags_set_disable_default_addr(vic_option_flags_t *bit_field,
					  bool		      val);

bool
vic_option_flags_get_disable_default_addr(const vic_option_flags_t *bit_field);

void
vic_option_flags_copy_disable_default_addr(
	vic_option_flags_t	 *bit_field_dst,
	const vic_option_flags_t *bit_field_src);

void
vic_option_flags_set_res0_0(vic_option_flags_t *bit_field, uint64_t val);

uint64_t
vic_option_flags_get_res0_0(const vic_option_flags_t *bit_field);

void
vic_option_flags_copy_res0_0(vic_option_flags_t	      *bit_field_dst,
			     const vic_option_flags_t *bit_field_src);

virtio_device_type_t
virtio_device_type_raw_cast(uint32_t val);

#define virtio_device_type_cast(val)                                           \
	virtio_device_type_raw_cast((uint32_t)(val))

virtio_device_type_result_t
virtio_device_type_raw_cast_safe(uint32_t val);

#define virtio_device_type_cast_safe(val)                                      \
	virtio_device_type_raw_cast_safe((uint32_t)(val))

bool
virtio_device_type_raw_is_valid(uint32_t val);

#define virtio_device_type_is_valid(val)                                       \
	virtio_device_type_raw_is_valid((uint32_t)(val))

virtio_transport_type_t
virtio_transport_type_raw_cast(uint32_t val);

#define virtio_transport_type_cast(val)                                        \
	virtio_transport_type_raw_cast((uint32_t)(val))

virtio_transport_type_result_t
virtio_transport_type_raw_cast_safe(uint32_t val);

#define virtio_transport_type_cast_safe(val)                                   \
	virtio_transport_type_raw_cast_safe((uint32_t)(val))

bool
virtio_transport_type_raw_is_valid(uint32_t val);

#define virtio_transport_type_is_valid(val)                                    \
	virtio_transport_type_raw_is_valid((uint32_t)(val))

void
virtio_backend_interface_type_set_device(
	virtio_backend_interface_type_t *bit_field, virtio_device_type_t val);

virtio_device_type_t
virtio_backend_interface_type_get_device(
	const virtio_backend_interface_type_t *bit_field);

void
virtio_backend_interface_type_copy_device(
	virtio_backend_interface_type_t	      *bit_field_dst,
	const virtio_backend_interface_type_t *bit_field_src);

void
virtio_backend_interface_type_set_transport(
	virtio_backend_interface_type_t *bit_field,
	virtio_transport_type_t		 val);

virtio_transport_type_t
virtio_backend_interface_type_get_transport(
	const virtio_backend_interface_type_t *bit_field);

void
virtio_backend_interface_type_copy_transport(
	virtio_backend_interface_type_t	      *bit_field_dst,
	const virtio_backend_interface_type_t *bit_field_src);

void
virtio_backend_interrupt_perqueue_set_queues_ready(
	virtio_backend_interrupt_perqueue_t *bit_field, uint64_t val);

uint64_t
virtio_backend_interrupt_perqueue_get_queues_ready(
	const virtio_backend_interrupt_perqueue_t *bit_field);

void
virtio_backend_interrupt_perqueue_copy_queues_ready(
	virtio_backend_interrupt_perqueue_t	  *bit_field_dst,
	const virtio_backend_interrupt_perqueue_t *bit_field_src);

void
virtio_backend_interrupt_perqueue_set_config_update(
	virtio_backend_interrupt_perqueue_t *bit_field, bool val);

bool
virtio_backend_interrupt_perqueue_get_config_update(
	const virtio_backend_interrupt_perqueue_t *bit_field);

void
virtio_backend_interrupt_perqueue_copy_config_update(
	virtio_backend_interrupt_perqueue_t	  *bit_field_dst,
	const virtio_backend_interrupt_perqueue_t *bit_field_src);

void
virtio_backend_memextent_layout_set_devcfg_size(
	virtio_backend_memextent_layout_t *bit_field, size_t val);

size_t
virtio_backend_memextent_layout_get_devcfg_size(
	const virtio_backend_memextent_layout_t *bit_field);

void
virtio_backend_memextent_layout_copy_devcfg_size(
	virtio_backend_memextent_layout_t	*bit_field_dst,
	const virtio_backend_memextent_layout_t *bit_field_src);

void
virtio_backend_memextent_layout_set_devcfg_offset(
	virtio_backend_memextent_layout_t *bit_field, size_t val);

size_t
virtio_backend_memextent_layout_get_devcfg_offset(
	const virtio_backend_memextent_layout_t *bit_field);

void
virtio_backend_memextent_layout_copy_devcfg_offset(
	virtio_backend_memextent_layout_t	*bit_field_dst,
	const virtio_backend_memextent_layout_t *bit_field_src);

void
virtio_backend_notify_flags_set_per_queue(
	virtio_backend_notify_flags_t *bit_field, bool val);

bool
virtio_backend_notify_flags_get_per_queue(
	const virtio_backend_notify_flags_t *bit_field);

void
virtio_backend_notify_flags_copy_per_queue(
	virtio_backend_notify_flags_t	    *bit_field_dst,
	const virtio_backend_notify_flags_t *bit_field_src);

void
virtio_backend_notify_flags_set_config_update(
	virtio_backend_notify_flags_t *bit_field, bool val);

bool
virtio_backend_notify_flags_get_config_update(
	const virtio_backend_notify_flags_t *bit_field);

void
virtio_backend_notify_flags_copy_config_update(
	virtio_backend_notify_flags_t	    *bit_field_dst,
	const virtio_backend_notify_flags_t *bit_field_src);

void
virtio_backend_notify_reason_set_new_buffer(
	virtio_backend_notify_reason_t *bit_field, bool val);

bool
virtio_backend_notify_reason_get_new_buffer(
	const virtio_backend_notify_reason_t *bit_field);

void
virtio_backend_notify_reason_copy_new_buffer(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src);

void
virtio_backend_notify_reason_set_reset_request(
	virtio_backend_notify_reason_t *bit_field, bool val);

bool
virtio_backend_notify_reason_get_reset_request(
	const virtio_backend_notify_reason_t *bit_field);

void
virtio_backend_notify_reason_copy_reset_request(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src);

bool
virtio_backend_notify_reason_get_res0_2(
	const virtio_backend_notify_reason_t *bit_field);

void
virtio_backend_notify_reason_set_driver_ok(
	virtio_backend_notify_reason_t *bit_field, bool val);

bool
virtio_backend_notify_reason_get_driver_ok(
	const virtio_backend_notify_reason_t *bit_field);

void
virtio_backend_notify_reason_copy_driver_ok(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src);

void
virtio_backend_notify_reason_set_failed(
	virtio_backend_notify_reason_t *bit_field, bool val);

bool
virtio_backend_notify_reason_get_failed(
	const virtio_backend_notify_reason_t *bit_field);

void
virtio_backend_notify_reason_copy_failed(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src);

void
virtio_interrupt_set_queue_ready(virtio_interrupt_t *bit_field, bool val);

bool
virtio_interrupt_get_queue_ready(const virtio_interrupt_t *bit_field);

void
virtio_interrupt_copy_queue_ready(virtio_interrupt_t	   *bit_field_dst,
				  const virtio_interrupt_t *bit_field_src);

void
virtio_interrupt_set_config_update(virtio_interrupt_t *bit_field, bool val);

bool
virtio_interrupt_get_config_update(const virtio_interrupt_t *bit_field);

void
virtio_interrupt_copy_config_update(virtio_interrupt_t	     *bit_field_dst,
				    const virtio_interrupt_t *bit_field_src);

void
virtio_backend_option_flags_set_sync_reset(
	virtio_backend_option_flags_t *bit_field, bool val);

bool
virtio_backend_option_flags_get_sync_reset(
	const virtio_backend_option_flags_t *bit_field);

void
virtio_backend_option_flags_copy_sync_reset(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src);

void
virtio_backend_option_flags_set_per_queue_irqs(
	virtio_backend_option_flags_t *bit_field, bool val);

bool
virtio_backend_option_flags_get_per_queue_irqs(
	const virtio_backend_option_flags_t *bit_field);

void
virtio_backend_option_flags_copy_per_queue_irqs(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src);

void
virtio_backend_option_flags_set_ignore_config_writes(
	virtio_backend_option_flags_t *bit_field, bool val);

bool
virtio_backend_option_flags_get_ignore_config_writes(
	const virtio_backend_option_flags_t *bit_field);

void
virtio_backend_option_flags_copy_ignore_config_writes(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src);

void
virtio_backend_option_flags_set_valid_me_layout(
	virtio_backend_option_flags_t *bit_field, bool val);

bool
virtio_backend_option_flags_get_valid_me_layout(
	const virtio_backend_option_flags_t *bit_field);

void
virtio_backend_option_flags_copy_valid_me_layout(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src);

void
virtio_backend_option_flags_set_valid_type(
	virtio_backend_option_flags_t *bit_field, bool val);

bool
virtio_backend_option_flags_get_valid_type(
	const virtio_backend_option_flags_t *bit_field);

void
virtio_backend_option_flags_copy_valid_type(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src);

void
virtio_iommu_options_set_max_streams(virtio_iommu_options_t *bit_field,
				     count_t		     val);

count_t
virtio_iommu_options_get_max_streams(const virtio_iommu_options_t *bit_field);

void
virtio_iommu_options_copy_max_streams(
	virtio_iommu_options_t	     *bit_field_dst,
	const virtio_iommu_options_t *bit_field_src);

bool
virtio_iommu_options_get_addrspace_valid(
	const virtio_iommu_options_t *bit_field);

void
virtio_status_set_acknowledge(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_acknowledge(const virtio_status_t *bit_field);

void
virtio_status_copy_acknowledge(virtio_status_t	     *bit_field_dst,
			       const virtio_status_t *bit_field_src);

void
virtio_status_set_driver(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_driver(const virtio_status_t *bit_field);

void
virtio_status_copy_driver(virtio_status_t	*bit_field_dst,
			  const virtio_status_t *bit_field_src);

void
virtio_status_set_driver_ok(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_driver_ok(const virtio_status_t *bit_field);

void
virtio_status_copy_driver_ok(virtio_status_t	   *bit_field_dst,
			     const virtio_status_t *bit_field_src);

void
virtio_status_set_features_ok(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_features_ok(const virtio_status_t *bit_field);

void
virtio_status_copy_features_ok(virtio_status_t	     *bit_field_dst,
			       const virtio_status_t *bit_field_src);

void
virtio_status_set_device_needs_reset(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_device_needs_reset(const virtio_status_t *bit_field);

void
virtio_status_copy_device_needs_reset(virtio_status_t	    *bit_field_dst,
				      const virtio_status_t *bit_field_src);

void
virtio_status_set_failed(virtio_status_t *bit_field, bool val);

bool
virtio_status_get_failed(const virtio_status_t *bit_field);

void
virtio_status_copy_failed(virtio_status_t	*bit_field_dst,
			  const virtio_status_t *bit_field_src);

void
vpci_aperture_set_bits(vpci_aperture_t *bit_field, count_t val);

count_t
vpci_aperture_get_bits(const vpci_aperture_t *bit_field);

void
vpci_aperture_copy_bits(vpci_aperture_t	      *bit_field_dst,
			const vpci_aperture_t *bit_field_src);

uint64_t
vpci_aperture_get_res0(const vpci_aperture_t *bit_field);

void
vpci_aperture_set_base(vpci_aperture_t *bit_field, vmaddr_t val);

vmaddr_t
vpci_aperture_get_base(const vpci_aperture_t *bit_field);

void
vpci_aperture_copy_base(vpci_aperture_t	      *bit_field_dst,
			const vpci_aperture_t *bit_field_src);

void
vpci_option_flags_set_pcie(vpci_option_flags_t *bit_field, bool val);

bool
vpci_option_flags_get_pcie(const vpci_option_flags_t *bit_field);

void
vpci_option_flags_copy_pcie(vpci_option_flags_t	      *bit_field_dst,
			    const vpci_option_flags_t *bit_field_src);

uint64_t
vpci_option_flags_get_res0(const vpci_option_flags_t *bit_field);

void
vpm_group_option_flags_set_no_aggregation(vpm_group_option_flags_t *bit_field,
					  bool			    val);

bool
vpm_group_option_flags_get_no_aggregation(
	const vpm_group_option_flags_t *bit_field);

void
vpm_group_option_flags_copy_no_aggregation(
	vpm_group_option_flags_t       *bit_field_dst,
	const vpm_group_option_flags_t *bit_field_src);

void
vpm_group_option_flags_set_explicit_wakeup(vpm_group_option_flags_t *bit_field,
					   bool			     val);

bool
vpm_group_option_flags_get_explicit_wakeup(
	const vpm_group_option_flags_t *bit_field);

void
vpm_group_option_flags_copy_explicit_wakeup(
	vpm_group_option_flags_t       *bit_field_dst,
	const vpm_group_option_flags_t *bit_field_src);

vpm_state_t
vpm_state_raw_cast(uint32_t val);

#define vpm_state_cast(val) vpm_state_raw_cast((uint32_t)(val))

vpm_state_result_t
vpm_state_raw_cast_safe(uint32_t val);

#define vpm_state_cast_safe(val) vpm_state_raw_cast_safe((uint32_t)(val))

bool
vpm_state_raw_is_valid(uint32_t val);

#define vpm_state_is_valid(val) vpm_state_raw_is_valid((uint32_t)(val))

void
watchdog_bind_option_flags_set_bite_virq(
	watchdog_bind_option_flags_t *bit_field, bool val);

bool
watchdog_bind_option_flags_get_bite_virq(
	const watchdog_bind_option_flags_t *bit_field);

void
watchdog_bind_option_flags_copy_bite_virq(
	watchdog_bind_option_flags_t	   *bit_field_dst,
	const watchdog_bind_option_flags_t *bit_field_src);

watchdog_manage_op_t
watchdog_manage_op_raw_cast(uint32_t val);

#define watchdog_manage_op_cast(val)                                           \
	watchdog_manage_op_raw_cast((uint32_t)(val))

watchdog_manage_op_result_t
watchdog_manage_op_raw_cast_safe(uint32_t val);

#define watchdog_manage_op_cast_safe(val)                                      \
	watchdog_manage_op_raw_cast_safe((uint32_t)(val))

bool
watchdog_manage_op_raw_is_valid(uint32_t val);

#define watchdog_manage_op_is_valid(val)                                       \
	watchdog_manage_op_raw_is_valid((uint32_t)(val))

void
watchdog_option_flags_set_critical_bite(watchdog_option_flags_t *bit_field,
					bool			 val);

bool
watchdog_option_flags_get_critical_bite(
	const watchdog_option_flags_t *bit_field);

void
watchdog_option_flags_copy_critical_bite(
	watchdog_option_flags_t	      *bit_field_dst,
	const watchdog_option_flags_t *bit_field_src);

void
watchdog_option_flags_set_fatal_bite(watchdog_option_flags_t *bit_field,
				     bool		      val);

bool
watchdog_option_flags_get_fatal_bite(const watchdog_option_flags_t *bit_field);

void
watchdog_option_flags_copy_fatal_bite(
	watchdog_option_flags_t	      *bit_field_dst,
	const watchdog_option_flags_t *bit_field_src);
#else
#error multiple include HYPTYPES_H_
#endif
