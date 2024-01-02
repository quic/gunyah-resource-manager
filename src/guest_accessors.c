// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

// Bitfield Accessors

void
addrspace_map_flags_init(addrspace_map_flags_t *bit_field)
{
	*bit_field = addrspace_map_flags_default();
}

uint32_t
addrspace_map_flags_raw(addrspace_map_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
addrspace_map_flags_atomic_ptr_raw(_Atomic addrspace_map_flags_t *ptr)
{
	return (_Atomic uint32_t *)&((addrspace_map_flags_t *)ptr)->bf[0];
}

addrspace_map_flags_t
addrspace_map_flags_clean(addrspace_map_flags_t bit_field)
{
	return (addrspace_map_flags_t){ .bf = {
						(bit_field.bf[0] & 0xffffffffU),
					} };
}

bool
addrspace_map_flags_is_equal(addrspace_map_flags_t b1, addrspace_map_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
addrspace_map_flags_set_partial(addrspace_map_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
addrspace_map_flags_get_partial(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_map_flags_copy_partial(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
addrspace_map_flags_set_no_sync(addrspace_map_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
addrspace_map_flags_get_no_sync(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_map_flags_copy_no_sync(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

uint64_t
addrspace_map_flags_get_res0_0(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x3fffffffU) << 0U;
	return (uint64_t)val;
}

void
hyp_api_info_init(hyp_api_info_t *bit_field)
{
	*bit_field = hyp_api_info_default();
}

uint64_t
hyp_api_info_raw(hyp_api_info_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
hyp_api_info_atomic_ptr_raw(_Atomic hyp_api_info_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_info_t *)ptr)->bf[0];
}

hyp_api_info_t
hyp_api_info_clean(hyp_api_info_t bit_field)
{
	return (hyp_api_info_t){ .bf = {
					 // (0x5100000000008001U &
					 // ~0xff0000000000ffffU) |
					 (uint64_t)(0x0U) |
						 (bit_field.bf[0] &
						  0xff0000000000ffffU),
				 } };
}

bool
hyp_api_info_is_equal(hyp_api_info_t b1, hyp_api_info_t b2)
{
	return ((b1.bf[0] & 0xff0000000000ffffU) ==
		(b2.bf[0] & 0xff0000000000ffffU));
}

uint16_t
hyp_api_info_get_api_version(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x3fffU) << 0U;
	return (uint16_t)val;
}

bool
hyp_api_info_get_big_endian(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 14U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_info_get_is_64bit(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 15U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

hyp_variant_t
hyp_api_info_get_variant(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 56U) & (uint64_t)0xffU) << 0U;
	return (hyp_variant_t)val;
}

void
hyp_api_flags0_init(hyp_api_flags0_t *bit_field)
{
	*bit_field = hyp_api_flags0_default();
}

uint64_t
hyp_api_flags0_raw(hyp_api_flags0_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
hyp_api_flags0_atomic_ptr_raw(_Atomic hyp_api_flags0_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags0_t *)ptr)->bf[0];
}

hyp_api_flags0_t
hyp_api_flags0_clean(hyp_api_flags0_t bit_field)
{
	return (hyp_api_flags0_t){ .bf = {
					   // (0x10000effU &
					   // ~0xffffffffffffffffU) |
					   (uint64_t)(0x0U) |
						   (bit_field.bf[0] &
						    0xffffffffffffffffU),
				   } };
}

bool
hyp_api_flags0_is_equal(hyp_api_flags0_t b1, hyp_api_flags0_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
hyp_api_flags0_get_watchdog(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_reserved_16(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

scheduler_variant_t
hyp_api_flags0_get_scheduler(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 28U) & (uint64_t)0xfU) << 0U;
	return (scheduler_variant_t)val;
}

uint64_t
hyp_api_flags0_get_res0_0(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 12U) & (uint64_t)0xfU) << 0U;
	val |= ((bf[0] >> 17U) & (uint64_t)0x7ffU) << 4U;
	val |= ((bf[0] >> 32U) & (uint64_t)0xffffffffU) << 15U;
	return (uint64_t)val;
}

bool
hyp_api_flags0_get_doorbell(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_msgqueue(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_partition_cspace(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_trace_ctrl(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_vcpu_run(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 11U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_vic(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_virtio_mmio(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 9U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_vpm(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_memextent(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_prng(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 10U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags0_get_vcpu(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
hyp_api_flags1_init(hyp_api_flags1_t *bit_field)
{
	*bit_field = hyp_api_flags1_default();
}

uint64_t
hyp_api_flags1_raw(hyp_api_flags1_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
hyp_api_flags1_atomic_ptr_raw(_Atomic hyp_api_flags1_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags1_t *)ptr)->bf[0];
}

hyp_api_flags1_t
hyp_api_flags1_clean(hyp_api_flags1_t bit_field)
{
	return (hyp_api_flags1_t){ .bf = {
					   (bit_field.bf[0] &
					    0xffffffffffffffffU),
				   } };
}

bool
hyp_api_flags1_is_equal(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

uint64_t
hyp_api_flags1_get_res0_0(const hyp_api_flags1_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffffffffffU) << 0U;
	return (uint64_t)val;
}

void
hyp_api_flags2_init(hyp_api_flags2_t *bit_field)
{
	*bit_field = hyp_api_flags2_default();
}

uint64_t
hyp_api_flags2_raw(hyp_api_flags2_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
hyp_api_flags2_atomic_ptr_raw(_Atomic hyp_api_flags2_t *ptr)
{
	return (_Atomic uint64_t *)&((hyp_api_flags2_t *)ptr)->bf[0];
}

hyp_api_flags2_t
hyp_api_flags2_clean(hyp_api_flags2_t bit_field)
{
	return (hyp_api_flags2_t){ .bf = {
					   (bit_field.bf[0] &
					    0xffffffffffffffffU),
				   } };
}

bool
hyp_api_flags2_is_equal(hyp_api_flags2_t b1, hyp_api_flags2_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

uint64_t
hyp_api_flags2_get_res0_0(const hyp_api_flags2_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffffffffffU) << 0U;
	return (uint64_t)val;
}

void
memextent_attrs_init(memextent_attrs_t *bit_field)
{
	*bit_field = memextent_attrs_default();
}

uint32_t
memextent_attrs_raw(memextent_attrs_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
memextent_attrs_atomic_ptr_raw(_Atomic memextent_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_attrs_t *)ptr)->bf[0];
}

memextent_attrs_t
memextent_attrs_clean(memextent_attrs_t bit_field)
{
	return (memextent_attrs_t){ .bf = {
					    (bit_field.bf[0] & 0xffffffffU),
				    } };
}

bool
memextent_attrs_is_equal(memextent_attrs_t b1, memextent_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
memextent_attrs_set_access(memextent_attrs_t *bit_field, pgtable_access_t val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_attrs_get_access(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_attrs_copy_access(memextent_attrs_t	    *bit_field_dst,
			    const memextent_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_attrs_set_memtype(memextent_attrs_t  *bit_field,
			    memextent_memtype_t val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffcffU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x3U) << 8U;
}

memextent_memtype_t
memextent_attrs_get_memtype(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0x3U) << 0U;
	return (memextent_memtype_t)val;
}

void
memextent_attrs_copy_memtype(memextent_attrs_t	     *bit_field_dst,
			     const memextent_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x300U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x300U;
}

void
memextent_attrs_set_type(memextent_attrs_t *bit_field, memextent_type_t val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffcffffU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x3U) << 16U;
}

memextent_type_t
memextent_attrs_get_type(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint32_t)0x3U) << 0U;
	return (memextent_type_t)val;
}

void
memextent_attrs_copy_type(memextent_attrs_t	  *bit_field_dst,
			  const memextent_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x30000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x30000U;
}

void
memextent_attrs_set_append(memextent_attrs_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
memextent_attrs_get_append(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
memextent_attrs_copy_append(memextent_attrs_t	    *bit_field_dst,
			    const memextent_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1fU) << 0U;
	val |= ((bf[0] >> 10U) & (uint32_t)0x3fU) << 5U;
	val |= ((bf[0] >> 18U) & (uint32_t)0x1fffU) << 11U;
	return (uint64_t)val;
}

void
memextent_mapping_attrs_init(memextent_mapping_attrs_t *bit_field)
{
	*bit_field = memextent_mapping_attrs_default();
}

uint32_t
memextent_mapping_attrs_raw(memextent_mapping_attrs_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
memextent_mapping_attrs_atomic_ptr_raw(_Atomic memextent_mapping_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_mapping_attrs_t *)ptr)->bf[0];
}

memextent_mapping_attrs_t
memextent_mapping_attrs_clean(memextent_mapping_attrs_t bit_field)
{
	return (memextent_mapping_attrs_t){ .bf = {
						    (bit_field.bf[0] &
						     0xffffffffU),
					    } };
}

bool
memextent_mapping_attrs_is_equal(memextent_mapping_attrs_t b1,
				 memextent_mapping_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
memextent_mapping_attrs_set_user_access(memextent_mapping_attrs_t *bit_field,
					pgtable_access_t	   val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_mapping_attrs_get_user_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_mapping_attrs_copy_user_access(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_mapping_attrs_set_kernel_access(memextent_mapping_attrs_t *bit_field,
					  pgtable_access_t	     val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff8fU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x7U) << 4U;
}

pgtable_access_t
memextent_mapping_attrs_get_kernel_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_mapping_attrs_copy_kernel_access(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x70U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x70U;
}

void
memextent_mapping_attrs_set_memtype(memextent_mapping_attrs_t *bit_field,
				    pgtable_vm_memtype_t       val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xff00ffffU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffU) << 16U;
}

pgtable_vm_memtype_t
memextent_mapping_attrs_get_memtype(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint32_t)0xffU) << 0U;
	return (pgtable_vm_memtype_t)val;
}

void
memextent_mapping_attrs_copy_memtype(
	memextent_mapping_attrs_t	*bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xff0000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xff0000U;
}

uint64_t
memextent_mapping_attrs_get_res_0(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	val |= ((bf[0] >> 7U) & (uint32_t)0x1ffU) << 1U;
	val |= ((bf[0] >> 24U) & (uint32_t)0xffU) << 10U;
	return (uint64_t)val;
}

void
memextent_access_attrs_init(memextent_access_attrs_t *bit_field)
{
	*bit_field = memextent_access_attrs_default();
}

uint32_t
memextent_access_attrs_raw(memextent_access_attrs_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
memextent_access_attrs_atomic_ptr_raw(_Atomic memextent_access_attrs_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_access_attrs_t *)ptr)->bf[0];
}

memextent_access_attrs_t
memextent_access_attrs_clean(memextent_access_attrs_t bit_field)
{
	return (memextent_access_attrs_t){ .bf = {
						   (bit_field.bf[0] &
						    0xffffffffU),
					   } };
}

bool
memextent_access_attrs_is_equal(memextent_access_attrs_t b1,
				memextent_access_attrs_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
memextent_access_attrs_set_user_access(memextent_access_attrs_t *bit_field,
				       pgtable_access_t		 val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_access_attrs_get_user_access(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_access_attrs_copy_user_access(
	memextent_access_attrs_t       *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_access_attrs_set_kernel_access(memextent_access_attrs_t *bit_field,
					 pgtable_access_t	   val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff8fU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x7U) << 4U;
}

pgtable_access_t
memextent_access_attrs_get_kernel_access(
	const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_access_attrs_copy_kernel_access(
	memextent_access_attrs_t       *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x70U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x70U;
}

uint64_t
memextent_access_attrs_get_res_0(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	val |= ((bf[0] >> 7U) & (uint32_t)0x1ffffffU) << 1U;
	return (uint64_t)val;
}

void
memextent_donate_options_init(memextent_donate_options_t *bit_field)
{
	*bit_field = memextent_donate_options_default();
}

uint32_t
memextent_donate_options_raw(memextent_donate_options_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
memextent_donate_options_atomic_ptr_raw(_Atomic memextent_donate_options_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_donate_options_t *)ptr)->bf[0];
}

memextent_donate_options_t
memextent_donate_options_clean(memextent_donate_options_t bit_field)
{
	return (memextent_donate_options_t){ .bf = {
						     (bit_field.bf[0] &
						      0xffffffffU),
					     } };
}

bool
memextent_donate_options_is_equal(memextent_donate_options_t b1,
				  memextent_donate_options_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
memextent_donate_options_set_type(memextent_donate_options_t *bit_field,
				  memextent_donate_type_t     val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff00U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffU) << 0U;
}

memextent_donate_type_t
memextent_donate_options_get_type(const memextent_donate_options_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffU) << 0U;
	return (memextent_donate_type_t)val;
}

void
memextent_donate_options_copy_type(
	memextent_donate_options_t	 *bit_field_dst,
	const memextent_donate_options_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffU;
}

uint64_t
memextent_donate_options_get_res_0(const memextent_donate_options_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0x7fffffU) << 0U;
	return (uint64_t)val;
}

void
memextent_donate_options_set_no_sync(memextent_donate_options_t *bit_field,
				     bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
memextent_donate_options_get_no_sync(const memextent_donate_options_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
memextent_donate_options_copy_no_sync(
	memextent_donate_options_t	 *bit_field_dst,
	const memextent_donate_options_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
memextent_modify_flags_init(memextent_modify_flags_t *bit_field)
{
	*bit_field = memextent_modify_flags_default();
}

uint32_t
memextent_modify_flags_raw(memextent_modify_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
memextent_modify_flags_atomic_ptr_raw(_Atomic memextent_modify_flags_t *ptr)
{
	return (_Atomic uint32_t *)&((memextent_modify_flags_t *)ptr)->bf[0];
}

memextent_modify_flags_t
memextent_modify_flags_clean(memextent_modify_flags_t bit_field)
{
	return (memextent_modify_flags_t){ .bf = {
						   (bit_field.bf[0] &
						    0xffffffffU),
					   } };
}

bool
memextent_modify_flags_is_equal(memextent_modify_flags_t b1,
				memextent_modify_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
memextent_modify_flags_set_op(memextent_modify_flags_t *bit_field,
			      memextent_modify_op_t	val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff00U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffU) << 0U;
}

memextent_modify_op_t
memextent_modify_flags_get_op(const memextent_modify_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffU) << 0U;
	return (memextent_modify_op_t)val;
}

void
memextent_modify_flags_copy_op(memextent_modify_flags_t	      *bit_field_dst,
			       const memextent_modify_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffU;
}

uint64_t
memextent_modify_flags_get_res_0(const memextent_modify_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0x7fffffU) << 0U;
	return (uint64_t)val;
}

void
memextent_modify_flags_set_no_sync(memextent_modify_flags_t *bit_field,
				   bool			     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
memextent_modify_flags_get_no_sync(const memextent_modify_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
memextent_modify_flags_copy_no_sync(
	memextent_modify_flags_t       *bit_field_dst,
	const memextent_modify_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
root_env_mmio_range_properties_init(root_env_mmio_range_properties_t *bit_field)
{
	*bit_field = root_env_mmio_range_properties_default();
}

uint64_t
root_env_mmio_range_properties_raw(root_env_mmio_range_properties_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
root_env_mmio_range_properties_atomic_ptr_raw(
	_Atomic root_env_mmio_range_properties_t *ptr)
{
	return (_Atomic uint64_t *)&((root_env_mmio_range_properties_t *)ptr)
		->bf[0];
}

root_env_mmio_range_properties_t
root_env_mmio_range_properties_clean(root_env_mmio_range_properties_t bit_field)
{
	return (root_env_mmio_range_properties_t){ .bf = {
							   (bit_field.bf[0] &
							    0x8000ff07ffffffffU),
						   } };
}

bool
root_env_mmio_range_properties_is_equal(root_env_mmio_range_properties_t b1,
					root_env_mmio_range_properties_t b2)
{
	return ((b1.bf[0] & 0x8000ff07ffffffffU) ==
		(b2.bf[0] & 0x8000ff07ffffffffU));
}

void
root_env_mmio_range_properties_set_num_pages(
	root_env_mmio_range_properties_t *bit_field, uint32_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffff00000000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffffffU) << 0U;
}

uint32_t
root_env_mmio_range_properties_get_num_pages(
	const root_env_mmio_range_properties_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffU) << 0U;
	return (uint32_t)val;
}

void
root_env_mmio_range_properties_copy_num_pages(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffffU;
}

void
root_env_mmio_range_properties_set_access(
	root_env_mmio_range_properties_t *bit_field, pgtable_access_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffff8ffffffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0x7U) << 32U;
}

pgtable_access_t
root_env_mmio_range_properties_get_access(
	const root_env_mmio_range_properties_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 32U) & (uint64_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
root_env_mmio_range_properties_copy_access(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x700000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x700000000U;
}

void
root_env_mmio_range_properties_set_res_s2pt_attr(
	root_env_mmio_range_properties_t *bit_field, uint8_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffff00ffffffffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffU) << 40U;
}

uint8_t
root_env_mmio_range_properties_get_res_s2pt_attr(
	const root_env_mmio_range_properties_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 40U) & (uint64_t)0xffU) << 0U;
	return (uint8_t)val;
}

void
root_env_mmio_range_properties_copy_res_s2pt_attr(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xff0000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xff0000000000U;
}

void
root_env_mmio_range_properties_set_non_exclusive(
	root_env_mmio_range_properties_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x7fffffffffffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 63U;
}

bool
root_env_mmio_range_properties_get_non_exclusive(
	const root_env_mmio_range_properties_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 63U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
root_env_mmio_range_properties_copy_non_exclusive(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8000000000000000U;
}

void
scheduler_yield_control_init(scheduler_yield_control_t *bit_field)
{
	*bit_field = scheduler_yield_control_default();
}

uint32_t
scheduler_yield_control_raw(scheduler_yield_control_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
scheduler_yield_control_atomic_ptr_raw(_Atomic scheduler_yield_control_t *ptr)
{
	return (_Atomic uint32_t *)&((scheduler_yield_control_t *)ptr)->bf[0];
}

scheduler_yield_control_t
scheduler_yield_control_clean(scheduler_yield_control_t bit_field)
{
	return (scheduler_yield_control_t){ .bf = {
						    (bit_field.bf[0] &
						     0x8000ffffU),
					    } };
}

bool
scheduler_yield_control_is_equal(scheduler_yield_control_t b1,
				 scheduler_yield_control_t b2)
{
	return ((b1.bf[0] & 0x8000ffffU) == (b2.bf[0] & 0x8000ffffU));
}

void
scheduler_yield_control_set_hint(scheduler_yield_control_t *bit_field,
				 scheduler_yield_hint_t	    val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffff0000U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffffU) << 0U;
}

scheduler_yield_hint_t
scheduler_yield_control_get_hint(const scheduler_yield_control_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffffU) << 0U;
	return (scheduler_yield_hint_t)val;
}

void
scheduler_yield_control_copy_hint(scheduler_yield_control_t *bit_field_dst,
				  const scheduler_yield_control_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffffU;
}

void
scheduler_yield_control_set_impl_def(scheduler_yield_control_t *bit_field,
				     bool			val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
scheduler_yield_control_get_impl_def(const scheduler_yield_control_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
scheduler_yield_control_copy_impl_def(
	scheduler_yield_control_t	*bit_field_dst,
	const scheduler_yield_control_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
smccc_function_id_init(smccc_function_id_t *bit_field)
{
	*bit_field = smccc_function_id_default();
}

uint32_t
smccc_function_id_raw(smccc_function_id_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
smccc_function_id_atomic_ptr_raw(_Atomic smccc_function_id_t *ptr)
{
	return (_Atomic uint32_t *)&((smccc_function_id_t *)ptr)->bf[0];
}

smccc_function_id_t
smccc_function_id_clean(smccc_function_id_t bit_field)
{
	return (smccc_function_id_t){ .bf = {
					      (bit_field.bf[0] & 0xffffffffU),
				      } };
}

bool
smccc_function_id_is_equal(smccc_function_id_t b1, smccc_function_id_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
smccc_function_id_set_function(smccc_function_id_t *bit_field,
			       smccc_function_t	    val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffff0000U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffffU) << 0U;
}

smccc_function_t
smccc_function_id_get_function(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffffU) << 0U;
	return (smccc_function_t)val;
}

void
smccc_function_id_copy_function(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffffU;
}

void
smccc_function_id_set_sve_live_state_hint(smccc_function_id_t *bit_field,
					  bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffeffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 16U;
}

bool
smccc_function_id_get_sve_live_state_hint(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
smccc_function_id_copy_sve_live_state_hint(
	smccc_function_id_t	  *bit_field_dst,
	const smccc_function_id_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10000U;
}

uint32_t
smccc_function_id_get_res0(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 17U) & (uint32_t)0x7fU) << 0U;
	return (uint32_t)val;
}

void
smccc_function_id_set_owner_id(smccc_function_id_t *bit_field,
			       smccc_owner_id_t	    val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xc0ffffffU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0x3fU) << 24U;
}

smccc_owner_id_t
smccc_function_id_get_owner_id(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 24U) & (uint32_t)0x3fU) << 0U;
	return (smccc_owner_id_t)val;
}

void
smccc_function_id_copy_owner_id(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x3f000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x3f000000U;
}

void
smccc_function_id_set_is_smc64(smccc_function_id_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xbfffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 30U;
}

bool
smccc_function_id_get_is_smc64(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 30U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
smccc_function_id_copy_is_smc64(smccc_function_id_t	  *bit_field_dst,
				const smccc_function_id_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x40000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x40000000U;
}

void
smccc_function_id_set_is_fast(smccc_function_id_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
smccc_function_id_get_is_fast(const smccc_function_id_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
smccc_function_id_copy_is_fast(smccc_function_id_t	 *bit_field_dst,
			       const smccc_function_id_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
smccc_vendor_hyp_function_id_init(smccc_vendor_hyp_function_id_t *bit_field)
{
	*bit_field = smccc_vendor_hyp_function_id_default();
}

uint16_t
smccc_vendor_hyp_function_id_raw(smccc_vendor_hyp_function_id_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint16_t *
smccc_vendor_hyp_function_id_atomic_ptr_raw(
	_Atomic smccc_vendor_hyp_function_id_t *ptr)
{
	return (_Atomic uint16_t *)&((smccc_vendor_hyp_function_id_t *)ptr)
		->bf[0];
}

smccc_vendor_hyp_function_id_t
smccc_vendor_hyp_function_id_clean(smccc_vendor_hyp_function_id_t bit_field)
{
	return (smccc_vendor_hyp_function_id_t){ .bf = {
							 (bit_field.bf[0] &
							  0xffffU),
						 } };
}

bool
smccc_vendor_hyp_function_id_is_equal(smccc_vendor_hyp_function_id_t b1,
				      smccc_vendor_hyp_function_id_t b2)
{
	return ((b1.bf[0] & 0xffffU) == (b2.bf[0] & 0xffffU));
}

void
smccc_vendor_hyp_function_id_set_call_class(
	smccc_vendor_hyp_function_id_t	 *bit_field,
	smccc_vendor_hyp_function_class_t val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0x3fffU;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0x3U) << 14U;
}

smccc_vendor_hyp_function_class_t
smccc_vendor_hyp_function_id_get_call_class(
	const smccc_vendor_hyp_function_id_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 14U) & (uint16_t)0x3U) << 0U;
	return (smccc_vendor_hyp_function_class_t)val;
}

void
smccc_vendor_hyp_function_id_copy_call_class(
	smccc_vendor_hyp_function_id_t	     *bit_field_dst,
	const smccc_vendor_hyp_function_id_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0xc000U;
	bf_dst[0] |= bf_src[0] & (uint16_t)0xc000U;
}

void
smccc_vendor_hyp_function_id_set_function(
	smccc_vendor_hyp_function_id_t *bit_field, uint16_t val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0xc000U;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0x3fffU) << 0U;
}

uint16_t
smccc_vendor_hyp_function_id_get_function(
	const smccc_vendor_hyp_function_id_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint16_t)0x3fffU) << 0U;
	return (uint16_t)val;
}

void
smccc_vendor_hyp_function_id_copy_function(
	smccc_vendor_hyp_function_id_t	     *bit_field_dst,
	const smccc_vendor_hyp_function_id_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0x3fffU;
	bf_dst[0] |= bf_src[0] & (uint16_t)0x3fffU;
}

void
vcpu_poweroff_flags_init(vcpu_poweroff_flags_t *bit_field)
{
	*bit_field = vcpu_poweroff_flags_default();
}

uint64_t
vcpu_poweroff_flags_raw(vcpu_poweroff_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vcpu_poweroff_flags_atomic_ptr_raw(_Atomic vcpu_poweroff_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vcpu_poweroff_flags_t *)ptr)->bf[0];
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_clean(vcpu_poweroff_flags_t bit_field)
{
	return (vcpu_poweroff_flags_t){ .bf = {
						(bit_field.bf[0] & 0x1U),
					} };
}

bool
vcpu_poweroff_flags_is_equal(vcpu_poweroff_flags_t b1, vcpu_poweroff_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
}

bool
vcpu_poweroff_flags_is_empty(vcpu_poweroff_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x1U) == 0U);
}

bool
vcpu_poweroff_flags_is_clean(vcpu_poweroff_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffeU) == 0x0U);
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_union(vcpu_poweroff_flags_t b1, vcpu_poweroff_flags_t b2)
{
	return (vcpu_poweroff_flags_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_intersection(vcpu_poweroff_flags_t b1,
				 vcpu_poweroff_flags_t b2)
{
	return (vcpu_poweroff_flags_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_inverse(vcpu_poweroff_flags_t b)
{
	return (vcpu_poweroff_flags_t){ .bf = {
						~b.bf[0],
					} };
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_difference(vcpu_poweroff_flags_t b1,
			       vcpu_poweroff_flags_t b2)
{
	vcpu_poweroff_flags_t not_b2 = vcpu_poweroff_flags_inverse(b2);
	return vcpu_poweroff_flags_intersection(b1, not_b2);
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_union(_Atomic vcpu_poweroff_flags_t *b1,
				 vcpu_poweroff_flags_t b2, memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_poweroff_flags_t *)b1)->bf[0];
	return (vcpu_poweroff_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_intersection(_Atomic vcpu_poweroff_flags_t *b1,
					vcpu_poweroff_flags_t	       b2,
					memory_order		       order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_poweroff_flags_t *)b1)->bf[0];
	return (vcpu_poweroff_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_difference(_Atomic vcpu_poweroff_flags_t *b1,
				      vcpu_poweroff_flags_t	     b2,
				      memory_order		     order)
{
	vcpu_poweroff_flags_t not_b2 = vcpu_poweroff_flags_inverse(b2);
	return vcpu_poweroff_flags_atomic_intersection(b1, not_b2, order);
}

void
vcpu_poweroff_flags_set_last_vcpu(vcpu_poweroff_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vcpu_poweroff_flags_get_last_vcpu(const vcpu_poweroff_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_poweroff_flags_copy_last_vcpu(vcpu_poweroff_flags_t       *bit_field_dst,
				   const vcpu_poweroff_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vcpu_option_flags_init(vcpu_option_flags_t *bit_field)
{
	*bit_field = vcpu_option_flags_default();
}

uint64_t
vcpu_option_flags_raw(vcpu_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vcpu_option_flags_atomic_ptr_raw(_Atomic vcpu_option_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vcpu_option_flags_t *)ptr)->bf[0];
}

vcpu_option_flags_t
vcpu_option_flags_clean(vcpu_option_flags_t bit_field)
{
	return (vcpu_option_flags_t){ .bf = {
					      (bit_field.bf[0] &
					       0x800000000000033fU),
				      } };
}

bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return ((b1.bf[0] & 0x800000000000033fU) ==
		(b2.bf[0] & 0x800000000000033fU));
}

bool
vcpu_option_flags_is_empty(vcpu_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x800000000000033fU) == 0U);
}

bool
vcpu_option_flags_is_clean(vcpu_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffffffffcc0U) == 0x0U);
}

vcpu_option_flags_t
vcpu_option_flags_union(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return (vcpu_option_flags_t){ .bf = {
					      b1.bf[0] | b2.bf[0],
				      } };
}

vcpu_option_flags_t
vcpu_option_flags_intersection(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return (vcpu_option_flags_t){ .bf = {
					      b1.bf[0] & b2.bf[0],
				      } };
}

vcpu_option_flags_t
vcpu_option_flags_inverse(vcpu_option_flags_t b)
{
	return (vcpu_option_flags_t){ .bf = {
					      ~b.bf[0],
				      } };
}

vcpu_option_flags_t
vcpu_option_flags_difference(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	vcpu_option_flags_t not_b2 = vcpu_option_flags_inverse(b2);
	return vcpu_option_flags_intersection(b1, not_b2);
}

vcpu_option_flags_t
vcpu_option_flags_atomic_union(_Atomic vcpu_option_flags_t *b1,
			       vcpu_option_flags_t b2, memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_option_flags_t *)b1)->bf[0];
	return (vcpu_option_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_option_flags_t
vcpu_option_flags_atomic_intersection(_Atomic vcpu_option_flags_t *b1,
				      vcpu_option_flags_t	   b2,
				      memory_order		   order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_option_flags_t *)b1)->bf[0];
	return (vcpu_option_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_option_flags_t
vcpu_option_flags_atomic_difference(_Atomic vcpu_option_flags_t *b1,
				    vcpu_option_flags_t b2, memory_order order)
{
	vcpu_option_flags_t not_b2 = vcpu_option_flags_inverse(b2);
	return vcpu_option_flags_atomic_intersection(b1, not_b2, order);
}

void
vcpu_option_flags_set_pinned(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vcpu_option_flags_get_pinned(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_pinned(vcpu_option_flags_t	*bit_field_dst,
			      const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vcpu_option_flags_set_critical(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffeffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 8U;
}

bool
vcpu_option_flags_get_critical(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_critical(vcpu_option_flags_t	  *bit_field_dst,
				const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x100U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x100U;
}

void
vcpu_option_flags_set_ras_error_handler(vcpu_option_flags_t *bit_field,
					bool		     val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vcpu_option_flags_get_ras_error_handler(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_ras_error_handler(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
vcpu_option_flags_set_amu_counting_disabled(vcpu_option_flags_t *bit_field,
					    bool		 val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 2U;
}

bool
vcpu_option_flags_get_amu_counting_disabled(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_amu_counting_disabled(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x4U;
}

void
vcpu_option_flags_set_sve_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
vcpu_option_flags_get_sve_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_sve_allowed(vcpu_option_flags_t	     *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
vcpu_option_flags_set_debug_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 4U;
}

bool
vcpu_option_flags_get_debug_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_debug_allowed(vcpu_option_flags_t       *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x10U;
}

void
vcpu_option_flags_set_trace_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffdfU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 5U;
}

bool
vcpu_option_flags_get_trace_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_trace_allowed(vcpu_option_flags_t       *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x20U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x20U;
}

void
vcpu_option_flags_set_hlos_vm(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x7fffffffffffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 63U;
}

bool
vcpu_option_flags_get_hlos_vm(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 63U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_hlos_vm(vcpu_option_flags_t	 *bit_field_dst,
			       const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8000000000000000U;
}

void
vcpu_option_flags_set_vcpu_run_scheduled(vcpu_option_flags_t *bit_field,
					 bool		      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffdffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 9U;
}

bool
vcpu_option_flags_get_vcpu_run_scheduled(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 9U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_vcpu_run_scheduled(
	vcpu_option_flags_t	  *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x200U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x200U;
}

void
vcpu_poweron_flags_init(vcpu_poweron_flags_t *bit_field)
{
	*bit_field = vcpu_poweron_flags_default();
}

uint64_t
vcpu_poweron_flags_raw(vcpu_poweron_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vcpu_poweron_flags_atomic_ptr_raw(_Atomic vcpu_poweron_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vcpu_poweron_flags_t *)ptr)->bf[0];
}

vcpu_poweron_flags_t
vcpu_poweron_flags_clean(vcpu_poweron_flags_t bit_field)
{
	return (vcpu_poweron_flags_t){ .bf = {
					       (bit_field.bf[0] & 0x3U),
				       } };
}

bool
vcpu_poweron_flags_is_equal(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
vcpu_poweron_flags_is_empty(vcpu_poweron_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
vcpu_poweron_flags_is_clean(vcpu_poweron_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

vcpu_poweron_flags_t
vcpu_poweron_flags_union(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2)
{
	return (vcpu_poweron_flags_t){ .bf = {
					       b1.bf[0] | b2.bf[0],
				       } };
}

vcpu_poweron_flags_t
vcpu_poweron_flags_intersection(vcpu_poweron_flags_t b1,
				vcpu_poweron_flags_t b2)
{
	return (vcpu_poweron_flags_t){ .bf = {
					       b1.bf[0] & b2.bf[0],
				       } };
}

vcpu_poweron_flags_t
vcpu_poweron_flags_inverse(vcpu_poweron_flags_t b)
{
	return (vcpu_poweron_flags_t){ .bf = {
					       ~b.bf[0],
				       } };
}

vcpu_poweron_flags_t
vcpu_poweron_flags_difference(vcpu_poweron_flags_t b1, vcpu_poweron_flags_t b2)
{
	vcpu_poweron_flags_t not_b2 = vcpu_poweron_flags_inverse(b2);
	return vcpu_poweron_flags_intersection(b1, not_b2);
}

vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_union(_Atomic vcpu_poweron_flags_t *b1,
				vcpu_poweron_flags_t b2, memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_poweron_flags_t *)b1)->bf[0];
	return (vcpu_poweron_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_intersection(_Atomic vcpu_poweron_flags_t *b1,
				       vcpu_poweron_flags_t	     b2,
				       memory_order		     order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vcpu_poweron_flags_t *)b1)->bf[0];
	return (vcpu_poweron_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_difference(_Atomic vcpu_poweron_flags_t *b1,
				     vcpu_poweron_flags_t	   b2,
				     memory_order		   order)
{
	vcpu_poweron_flags_t not_b2 = vcpu_poweron_flags_inverse(b2);
	return vcpu_poweron_flags_atomic_intersection(b1, not_b2, order);
}

void
vcpu_poweron_flags_set_preserve_entry_point(vcpu_poweron_flags_t *bit_field,
					    bool		  val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vcpu_poweron_flags_get_preserve_entry_point(
	const vcpu_poweron_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_poweron_flags_copy_preserve_entry_point(
	vcpu_poweron_flags_t	   *bit_field_dst,
	const vcpu_poweron_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vcpu_poweron_flags_set_preserve_context(vcpu_poweron_flags_t *bit_field,
					bool		      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vcpu_poweron_flags_get_preserve_context(const vcpu_poweron_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_poweron_flags_copy_preserve_context(
	vcpu_poweron_flags_t	   *bit_field_dst,
	const vcpu_poweron_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
vcpu_run_poweroff_flags_init(vcpu_run_poweroff_flags_t *bit_field)
{
	*bit_field = vcpu_run_poweroff_flags_default();
}

uint32_t
vcpu_run_poweroff_flags_raw(vcpu_run_poweroff_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
vcpu_run_poweroff_flags_atomic_ptr_raw(_Atomic vcpu_run_poweroff_flags_t *ptr)
{
	return (_Atomic uint32_t *)&((vcpu_run_poweroff_flags_t *)ptr)->bf[0];
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_clean(vcpu_run_poweroff_flags_t bit_field)
{
	return (vcpu_run_poweroff_flags_t){ .bf = {
						    (bit_field.bf[0] & 0x1U),
					    } };
}

bool
vcpu_run_poweroff_flags_is_equal(vcpu_run_poweroff_flags_t b1,
				 vcpu_run_poweroff_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
}

bool
vcpu_run_poweroff_flags_is_empty(vcpu_run_poweroff_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x1U) == 0U);
}

bool
vcpu_run_poweroff_flags_is_clean(vcpu_run_poweroff_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffeU) == 0x0U);
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_union(vcpu_run_poweroff_flags_t b1,
			      vcpu_run_poweroff_flags_t b2)
{
	return (vcpu_run_poweroff_flags_t){ .bf = {
						    b1.bf[0] | b2.bf[0],
					    } };
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_intersection(vcpu_run_poweroff_flags_t b1,
				     vcpu_run_poweroff_flags_t b2)
{
	return (vcpu_run_poweroff_flags_t){ .bf = {
						    b1.bf[0] & b2.bf[0],
					    } };
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_inverse(vcpu_run_poweroff_flags_t b)
{
	return (vcpu_run_poweroff_flags_t){ .bf = {
						    ~b.bf[0],
					    } };
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_difference(vcpu_run_poweroff_flags_t b1,
				   vcpu_run_poweroff_flags_t b2)
{
	vcpu_run_poweroff_flags_t not_b2 = vcpu_run_poweroff_flags_inverse(b2);
	return vcpu_run_poweroff_flags_intersection(b1, not_b2);
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_union(_Atomic vcpu_run_poweroff_flags_t *b1,
				     vcpu_run_poweroff_flags_t		b2,
				     memory_order			order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((vcpu_run_poweroff_flags_t *)b1)->bf[0];
	return (vcpu_run_poweroff_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_intersection(
	_Atomic vcpu_run_poweroff_flags_t *b1, vcpu_run_poweroff_flags_t b2,
	memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((vcpu_run_poweroff_flags_t *)b1)->bf[0];
	return (vcpu_run_poweroff_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_difference(_Atomic vcpu_run_poweroff_flags_t *b1,
					  vcpu_run_poweroff_flags_t	     b2,
					  memory_order order)
{
	vcpu_run_poweroff_flags_t not_b2 = vcpu_run_poweroff_flags_inverse(b2);
	return vcpu_run_poweroff_flags_atomic_intersection(b1, not_b2, order);
}

void
vcpu_run_poweroff_flags_set_exited(vcpu_run_poweroff_flags_t *bit_field,
				   bool			      val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
vcpu_run_poweroff_flags_get_exited(const vcpu_run_poweroff_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
vcpu_run_poweroff_flags_copy_exited(
	vcpu_run_poweroff_flags_t	*bit_field_dst,
	const vcpu_run_poweroff_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
vic_option_flags_init(vic_option_flags_t *bit_field)
{
	*bit_field = vic_option_flags_default();
}

uint64_t
vic_option_flags_raw(vic_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vic_option_flags_atomic_ptr_raw(_Atomic vic_option_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vic_option_flags_t *)ptr)->bf[0];
}

vic_option_flags_t
vic_option_flags_clean(vic_option_flags_t bit_field)
{
	return (vic_option_flags_t){ .bf = {
					     // (0x3U & ~0xffffffffffffffffU) |
					     (uint64_t)(0x0U) |
						     (bit_field.bf[0] &
						      0xffffffffffffffffU),
				     } };
}

bool
vic_option_flags_is_equal(vic_option_flags_t b1, vic_option_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

void
vic_option_flags_set_max_msis_valid(vic_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vic_option_flags_get_max_msis_valid(const vic_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vic_option_flags_copy_max_msis_valid(vic_option_flags_t	      *bit_field_dst,
				     const vic_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vic_option_flags_set_disable_default_addr(vic_option_flags_t *bit_field,
					  bool		      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vic_option_flags_get_disable_default_addr(const vic_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vic_option_flags_copy_disable_default_addr(
	vic_option_flags_t	 *bit_field_dst,
	const vic_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
vic_option_flags_set_res0_0(vic_option_flags_t *bit_field, uint64_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x3U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0x3fffffffffffffffU) << 2U;
}

uint64_t
vic_option_flags_get_res0_0(const vic_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x3fffffffffffffffU) << 0U;
	return (uint64_t)val;
}

void
vic_option_flags_copy_res0_0(vic_option_flags_t	      *bit_field_dst,
			     const vic_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xfffffffffffffffcU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xfffffffffffffffcU;
}

void
virtio_mmio_notify_reason_init(virtio_mmio_notify_reason_t *bit_field)
{
	*bit_field = virtio_mmio_notify_reason_default();
}

uint64_t
virtio_mmio_notify_reason_raw(virtio_mmio_notify_reason_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
virtio_mmio_notify_reason_atomic_ptr_raw(
	_Atomic virtio_mmio_notify_reason_t *ptr)
{
	return (_Atomic uint64_t *)&((virtio_mmio_notify_reason_t *)ptr)->bf[0];
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_clean(virtio_mmio_notify_reason_t bit_field)
{
	return (virtio_mmio_notify_reason_t){ .bf = {
						      (bit_field.bf[0] & 0x1fU),
					      } };
}

bool
virtio_mmio_notify_reason_is_equal(virtio_mmio_notify_reason_t b1,
				   virtio_mmio_notify_reason_t b2)
{
	return ((b1.bf[0] & 0x1fU) == (b2.bf[0] & 0x1fU));
}

bool
virtio_mmio_notify_reason_is_empty(virtio_mmio_notify_reason_t bit_field)
{
	return ((bit_field.bf[0] & 0x1fU) == 0U);
}

bool
virtio_mmio_notify_reason_is_clean(virtio_mmio_notify_reason_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffffffffffe0U) == 0x0U);
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_union(virtio_mmio_notify_reason_t b1,
				virtio_mmio_notify_reason_t b2)
{
	return (virtio_mmio_notify_reason_t){ .bf = {
						      b1.bf[0] | b2.bf[0],
					      } };
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_intersection(virtio_mmio_notify_reason_t b1,
				       virtio_mmio_notify_reason_t b2)
{
	return (virtio_mmio_notify_reason_t){ .bf = {
						      b1.bf[0] & b2.bf[0],
					      } };
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_inverse(virtio_mmio_notify_reason_t b)
{
	return (virtio_mmio_notify_reason_t){ .bf = {
						      ~b.bf[0],
					      } };
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_difference(virtio_mmio_notify_reason_t b1,
				     virtio_mmio_notify_reason_t b2)
{
	virtio_mmio_notify_reason_t not_b2 =
		virtio_mmio_notify_reason_inverse(b2);
	return virtio_mmio_notify_reason_intersection(b1, not_b2);
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_atomic_union(_Atomic virtio_mmio_notify_reason_t *b1,
				       virtio_mmio_notify_reason_t	    b2,
				       memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((virtio_mmio_notify_reason_t *)b1)->bf[0];
	return (virtio_mmio_notify_reason_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_atomic_intersection(
	_Atomic virtio_mmio_notify_reason_t *b1, virtio_mmio_notify_reason_t b2,
	memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((virtio_mmio_notify_reason_t *)b1)->bf[0];
	return (virtio_mmio_notify_reason_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

virtio_mmio_notify_reason_t
virtio_mmio_notify_reason_atomic_difference(
	_Atomic virtio_mmio_notify_reason_t *b1, virtio_mmio_notify_reason_t b2,
	memory_order order)
{
	virtio_mmio_notify_reason_t not_b2 =
		virtio_mmio_notify_reason_inverse(b2);
	return virtio_mmio_notify_reason_atomic_intersection(b1, not_b2, order);
}

void
virtio_mmio_notify_reason_set_new_buffer(virtio_mmio_notify_reason_t *bit_field,
					 bool			      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
virtio_mmio_notify_reason_get_new_buffer(
	const virtio_mmio_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_mmio_notify_reason_copy_new_buffer(
	virtio_mmio_notify_reason_t	  *bit_field_dst,
	const virtio_mmio_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
virtio_mmio_notify_reason_set_reset_rqst(virtio_mmio_notify_reason_t *bit_field,
					 bool			      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
virtio_mmio_notify_reason_get_reset_rqst(
	const virtio_mmio_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_mmio_notify_reason_copy_reset_rqst(
	virtio_mmio_notify_reason_t	  *bit_field_dst,
	const virtio_mmio_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

bool
virtio_mmio_notify_reason_get_res0_irq_ack(
	const virtio_mmio_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_mmio_notify_reason_set_driver_ok(virtio_mmio_notify_reason_t *bit_field,
					bool			     val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
virtio_mmio_notify_reason_get_driver_ok(
	const virtio_mmio_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_mmio_notify_reason_copy_driver_ok(
	virtio_mmio_notify_reason_t	  *bit_field_dst,
	const virtio_mmio_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
virtio_mmio_notify_reason_set_failed(virtio_mmio_notify_reason_t *bit_field,
				     bool			  val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 4U;
}

bool
virtio_mmio_notify_reason_get_failed(
	const virtio_mmio_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_mmio_notify_reason_copy_failed(
	virtio_mmio_notify_reason_t	  *bit_field_dst,
	const virtio_mmio_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x10U;
}

void
virtio_option_flags_init(virtio_option_flags_t *bit_field)
{
	*bit_field = virtio_option_flags_default();
}

uint64_t
virtio_option_flags_raw(virtio_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
virtio_option_flags_atomic_ptr_raw(_Atomic virtio_option_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((virtio_option_flags_t *)ptr)->bf[0];
}

virtio_option_flags_t
virtio_option_flags_clean(virtio_option_flags_t bit_field)
{
	return (virtio_option_flags_t){ .bf = {
						(bit_field.bf[0] &
						 0xffffffffffffffc0U),
					} };
}

bool
virtio_option_flags_is_equal(virtio_option_flags_t b1, virtio_option_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffc0U) ==
		(b2.bf[0] & 0xffffffffffffffc0U));
}

void
virtio_option_flags_set_valid_device_type(virtio_option_flags_t *bit_field,
					  bool			 val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffbfU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 6U;
}

bool
virtio_option_flags_get_valid_device_type(const virtio_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_option_flags_copy_valid_device_type(
	virtio_option_flags_t	    *bit_field_dst,
	const virtio_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x40U;
}

void
virtio_option_flags_set_res0(virtio_option_flags_t *bit_field, uint64_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x7fU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0x1ffffffffffffffU) << 7U;
}

uint64_t
virtio_option_flags_get_res0(const virtio_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint64_t)0x1ffffffffffffffU) << 0U;
	return (uint64_t)val;
}

void
virtio_option_flags_copy_res0(virtio_option_flags_t	  *bit_field_dst,
			      const virtio_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffffffffff80U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffffffffff80U;
}

void
vpm_group_option_flags_init(vpm_group_option_flags_t *bit_field)
{
	*bit_field = vpm_group_option_flags_default();
}

uint64_t
vpm_group_option_flags_raw(vpm_group_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vpm_group_option_flags_atomic_ptr_raw(_Atomic vpm_group_option_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vpm_group_option_flags_t *)ptr)->bf[0];
}

vpm_group_option_flags_t
vpm_group_option_flags_clean(vpm_group_option_flags_t bit_field)
{
	return (vpm_group_option_flags_t){ .bf = {
						   (bit_field.bf[0] & 0x1U),
					   } };
}

bool
vpm_group_option_flags_is_equal(vpm_group_option_flags_t b1,
				vpm_group_option_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
}

bool
vpm_group_option_flags_is_empty(vpm_group_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x1U) == 0U);
}

bool
vpm_group_option_flags_is_clean(vpm_group_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffeU) == 0x0U);
}

vpm_group_option_flags_t
vpm_group_option_flags_union(vpm_group_option_flags_t b1,
			     vpm_group_option_flags_t b2)
{
	return (vpm_group_option_flags_t){ .bf = {
						   b1.bf[0] | b2.bf[0],
					   } };
}

vpm_group_option_flags_t
vpm_group_option_flags_intersection(vpm_group_option_flags_t b1,
				    vpm_group_option_flags_t b2)
{
	return (vpm_group_option_flags_t){ .bf = {
						   b1.bf[0] & b2.bf[0],
					   } };
}

vpm_group_option_flags_t
vpm_group_option_flags_inverse(vpm_group_option_flags_t b)
{
	return (vpm_group_option_flags_t){ .bf = {
						   ~b.bf[0],
					   } };
}

vpm_group_option_flags_t
vpm_group_option_flags_difference(vpm_group_option_flags_t b1,
				  vpm_group_option_flags_t b2)
{
	vpm_group_option_flags_t not_b2 = vpm_group_option_flags_inverse(b2);
	return vpm_group_option_flags_intersection(b1, not_b2);
}

vpm_group_option_flags_t
vpm_group_option_flags_atomic_union(_Atomic vpm_group_option_flags_t *b1,
				    vpm_group_option_flags_t	      b2,
				    memory_order		      order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vpm_group_option_flags_t *)b1)->bf[0];
	return (vpm_group_option_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vpm_group_option_flags_t
vpm_group_option_flags_atomic_intersection(_Atomic vpm_group_option_flags_t *b1,
					   vpm_group_option_flags_t	     b2,
					   memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vpm_group_option_flags_t *)b1)->bf[0];
	return (vpm_group_option_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vpm_group_option_flags_t
vpm_group_option_flags_atomic_difference(_Atomic vpm_group_option_flags_t *b1,
					 vpm_group_option_flags_t	   b2,
					 memory_order order)
{
	vpm_group_option_flags_t not_b2 = vpm_group_option_flags_inverse(b2);
	return vpm_group_option_flags_atomic_intersection(b1, not_b2, order);
}

void
vpm_group_option_flags_set_no_aggregation(vpm_group_option_flags_t *bit_field,
					  bool			    val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vpm_group_option_flags_get_no_aggregation(
	const vpm_group_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vpm_group_option_flags_copy_no_aggregation(
	vpm_group_option_flags_t       *bit_field_dst,
	const vpm_group_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
msgqueue_create_info_init(msgqueue_create_info_t *bit_field)
{
	*bit_field = msgqueue_create_info_default();
}

uint64_t
msgqueue_create_info_raw(msgqueue_create_info_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
msgqueue_create_info_atomic_ptr_raw(_Atomic msgqueue_create_info_t *ptr)
{
	return (_Atomic uint64_t *)&((msgqueue_create_info_t *)ptr)->bf[0];
}

msgqueue_create_info_t
msgqueue_create_info_clean(msgqueue_create_info_t bit_field)
{
	return (msgqueue_create_info_t){ .bf = {
						 (bit_field.bf[0] & 0xffffffffU),
					 } };
}

bool
msgqueue_create_info_is_equal(msgqueue_create_info_t b1,
			      msgqueue_create_info_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

void
msgqueue_create_info_set_queue_depth(msgqueue_create_info_t *bit_field,
				     uint16_t		     val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffff0000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffU) << 0U;
}

uint16_t
msgqueue_create_info_get_queue_depth(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffU) << 0U;
	return (uint16_t)val;
}

void
msgqueue_create_info_copy_queue_depth(
	msgqueue_create_info_t	     *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffU;
}

void
msgqueue_create_info_set_max_msg_size(msgqueue_create_info_t *bit_field,
				      uint16_t		      val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffff0000ffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffU) << 16U;
}

uint16_t
msgqueue_create_info_get_max_msg_size(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0xffffU) << 0U;
	return (uint16_t)val;
}

void
msgqueue_create_info_copy_max_msg_size(
	msgqueue_create_info_t	     *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffff0000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffff0000U;
}

void
msgqueue_send_flags_init(msgqueue_send_flags_t *bit_field)
{
	*bit_field = msgqueue_send_flags_default();
}

uint32_t
msgqueue_send_flags_raw(msgqueue_send_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
msgqueue_send_flags_atomic_ptr_raw(_Atomic msgqueue_send_flags_t *ptr)
{
	return (_Atomic uint32_t *)&((msgqueue_send_flags_t *)ptr)->bf[0];
}

msgqueue_send_flags_t
msgqueue_send_flags_clean(msgqueue_send_flags_t bit_field)
{
	return (msgqueue_send_flags_t){ .bf = {
						(bit_field.bf[0] & 0x1U),
					} };
}

bool
msgqueue_send_flags_is_equal(msgqueue_send_flags_t b1, msgqueue_send_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
}

bool
msgqueue_send_flags_is_empty(msgqueue_send_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x1U) == 0U);
}

bool
msgqueue_send_flags_is_clean(msgqueue_send_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffeU) == 0x0U);
}

msgqueue_send_flags_t
msgqueue_send_flags_union(msgqueue_send_flags_t b1, msgqueue_send_flags_t b2)
{
	return (msgqueue_send_flags_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

msgqueue_send_flags_t
msgqueue_send_flags_intersection(msgqueue_send_flags_t b1,
				 msgqueue_send_flags_t b2)
{
	return (msgqueue_send_flags_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

msgqueue_send_flags_t
msgqueue_send_flags_inverse(msgqueue_send_flags_t b)
{
	return (msgqueue_send_flags_t){ .bf = {
						~b.bf[0],
					} };
}

msgqueue_send_flags_t
msgqueue_send_flags_difference(msgqueue_send_flags_t b1,
			       msgqueue_send_flags_t b2)
{
	msgqueue_send_flags_t not_b2 = msgqueue_send_flags_inverse(b2);
	return msgqueue_send_flags_intersection(b1, not_b2);
}

msgqueue_send_flags_t
msgqueue_send_flags_atomic_union(_Atomic msgqueue_send_flags_t *b1,
				 msgqueue_send_flags_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((msgqueue_send_flags_t *)b1)->bf[0];
	return (msgqueue_send_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

msgqueue_send_flags_t
msgqueue_send_flags_atomic_intersection(_Atomic msgqueue_send_flags_t *b1,
					msgqueue_send_flags_t	       b2,
					memory_order		       order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((msgqueue_send_flags_t *)b1)->bf[0];
	return (msgqueue_send_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

msgqueue_send_flags_t
msgqueue_send_flags_atomic_difference(_Atomic msgqueue_send_flags_t *b1,
				      msgqueue_send_flags_t	     b2,
				      memory_order		     order)
{
	msgqueue_send_flags_t not_b2 = msgqueue_send_flags_inverse(b2);
	return msgqueue_send_flags_atomic_intersection(b1, not_b2, order);
}

void
msgqueue_send_flags_set_push(msgqueue_send_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
msgqueue_send_flags_get_push(const msgqueue_send_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
msgqueue_send_flags_copy_push(msgqueue_send_flags_t	  *bit_field_dst,
			      const msgqueue_send_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
vgic_gicr_attach_flags_init(vgic_gicr_attach_flags_t *bit_field)
{
	*bit_field = vgic_gicr_attach_flags_default();
}

uint64_t
vgic_gicr_attach_flags_raw(vgic_gicr_attach_flags_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint64_t *
vgic_gicr_attach_flags_atomic_ptr_raw(_Atomic vgic_gicr_attach_flags_t *ptr)
{
	return (_Atomic uint64_t *)&((vgic_gicr_attach_flags_t *)ptr)->bf[0];
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_clean(vgic_gicr_attach_flags_t bit_field)
{
	return (vgic_gicr_attach_flags_t){ .bf = {
						   (bit_field.bf[0] & 0x3U),
					   } };
}

bool
vgic_gicr_attach_flags_is_equal(vgic_gicr_attach_flags_t b1,
				vgic_gicr_attach_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
vgic_gicr_attach_flags_is_empty(vgic_gicr_attach_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
vgic_gicr_attach_flags_is_clean(vgic_gicr_attach_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_union(vgic_gicr_attach_flags_t b1,
			     vgic_gicr_attach_flags_t b2)
{
	return (vgic_gicr_attach_flags_t){ .bf = {
						   b1.bf[0] | b2.bf[0],
					   } };
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_intersection(vgic_gicr_attach_flags_t b1,
				    vgic_gicr_attach_flags_t b2)
{
	return (vgic_gicr_attach_flags_t){ .bf = {
						   b1.bf[0] & b2.bf[0],
					   } };
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_inverse(vgic_gicr_attach_flags_t b)
{
	return (vgic_gicr_attach_flags_t){ .bf = {
						   ~b.bf[0],
					   } };
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_difference(vgic_gicr_attach_flags_t b1,
				  vgic_gicr_attach_flags_t b2)
{
	vgic_gicr_attach_flags_t not_b2 = vgic_gicr_attach_flags_inverse(b2);
	return vgic_gicr_attach_flags_intersection(b1, not_b2);
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_union(_Atomic vgic_gicr_attach_flags_t *b1,
				    vgic_gicr_attach_flags_t	      b2,
				    memory_order		      order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vgic_gicr_attach_flags_t *)b1)->bf[0];
	return (vgic_gicr_attach_flags_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_intersection(_Atomic vgic_gicr_attach_flags_t *b1,
					   vgic_gicr_attach_flags_t	     b2,
					   memory_order order)
{
	_Atomic uint64_t *bf =
		(_Atomic uint64_t *)&((vgic_gicr_attach_flags_t *)b1)->bf[0];
	return (vgic_gicr_attach_flags_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_difference(_Atomic vgic_gicr_attach_flags_t *b1,
					 vgic_gicr_attach_flags_t	   b2,
					 memory_order order)
{
	vgic_gicr_attach_flags_t not_b2 = vgic_gicr_attach_flags_inverse(b2);
	return vgic_gicr_attach_flags_atomic_intersection(b1, not_b2, order);
}

void
vgic_gicr_attach_flags_set_last_valid(vgic_gicr_attach_flags_t *bit_field,
				      bool			val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vgic_gicr_attach_flags_get_last_valid(const vgic_gicr_attach_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vgic_gicr_attach_flags_copy_last_valid(
	vgic_gicr_attach_flags_t       *bit_field_dst,
	const vgic_gicr_attach_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vgic_gicr_attach_flags_set_last(vgic_gicr_attach_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vgic_gicr_attach_flags_get_last(const vgic_gicr_attach_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vgic_gicr_attach_flags_copy_last(vgic_gicr_attach_flags_t	*bit_field_dst,
				 const vgic_gicr_attach_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
cap_rights_generic_init(cap_rights_generic_t *bit_field)
{
	*bit_field = cap_rights_generic_default();
}

uint32_t
cap_rights_generic_raw(cap_rights_generic_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_generic_atomic_ptr_raw(_Atomic cap_rights_generic_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_generic_t *)ptr)->bf[0];
}

cap_rights_generic_t
cap_rights_generic_clean(cap_rights_generic_t bit_field)
{
	return (cap_rights_generic_t){ .bf = {
					       (bit_field.bf[0] & 0x80000000U),
				       } };
}

bool
cap_rights_generic_is_equal(cap_rights_generic_t b1, cap_rights_generic_t b2)
{
	return ((b1.bf[0] & 0x80000000U) == (b2.bf[0] & 0x80000000U));
}

bool
cap_rights_generic_is_empty(cap_rights_generic_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000000U) == 0U);
}

bool
cap_rights_generic_is_clean(cap_rights_generic_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffffU) == 0x0U);
}

cap_rights_generic_t
cap_rights_generic_union(cap_rights_generic_t b1, cap_rights_generic_t b2)
{
	return (cap_rights_generic_t){ .bf = {
					       b1.bf[0] | b2.bf[0],
				       } };
}

cap_rights_generic_t
cap_rights_generic_intersection(cap_rights_generic_t b1,
				cap_rights_generic_t b2)
{
	return (cap_rights_generic_t){ .bf = {
					       b1.bf[0] & b2.bf[0],
				       } };
}

cap_rights_generic_t
cap_rights_generic_inverse(cap_rights_generic_t b)
{
	return (cap_rights_generic_t){ .bf = {
					       ~b.bf[0],
				       } };
}

cap_rights_generic_t
cap_rights_generic_difference(cap_rights_generic_t b1, cap_rights_generic_t b2)
{
	cap_rights_generic_t not_b2 = cap_rights_generic_inverse(b2);
	return cap_rights_generic_intersection(b1, not_b2);
}

cap_rights_generic_t
cap_rights_generic_atomic_union(_Atomic cap_rights_generic_t *b1,
				cap_rights_generic_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_generic_t *)b1)->bf[0];
	return (cap_rights_generic_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_generic_t
cap_rights_generic_atomic_intersection(_Atomic cap_rights_generic_t *b1,
				       cap_rights_generic_t	     b2,
				       memory_order		     order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_generic_t *)b1)->bf[0];
	return (cap_rights_generic_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_generic_t
cap_rights_generic_atomic_difference(_Atomic cap_rights_generic_t *b1,
				     cap_rights_generic_t	   b2,
				     memory_order		   order)
{
	cap_rights_generic_t not_b2 = cap_rights_generic_inverse(b2);
	return cap_rights_generic_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_generic_set_object_activate(cap_rights_generic_t *bit_field,
				       bool		     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_generic_get_object_activate(const cap_rights_generic_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_generic_copy_object_activate(
	cap_rights_generic_t	   *bit_field_dst,
	const cap_rights_generic_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_addrspace_init(cap_rights_addrspace_t *bit_field)
{
	*bit_field = cap_rights_addrspace_default();
}

uint32_t
cap_rights_addrspace_raw(cap_rights_addrspace_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_addrspace_atomic_ptr_raw(_Atomic cap_rights_addrspace_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_addrspace_t *)ptr)->bf[0];
}

cap_rights_addrspace_t
cap_rights_addrspace_clean(cap_rights_addrspace_t bit_field)
{
	return (cap_rights_addrspace_t){ .bf = {
						 (bit_field.bf[0] & 0x8000000fU),
					 } };
}

bool
cap_rights_addrspace_is_equal(cap_rights_addrspace_t b1,
			      cap_rights_addrspace_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
}

bool
cap_rights_addrspace_is_empty(cap_rights_addrspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000fU) == 0U);
}

bool
cap_rights_addrspace_is_clean(cap_rights_addrspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff0U) == 0x0U);
}

cap_rights_addrspace_t
cap_rights_addrspace_union(cap_rights_addrspace_t b1, cap_rights_addrspace_t b2)
{
	return (cap_rights_addrspace_t){ .bf = {
						 b1.bf[0] | b2.bf[0],
					 } };
}

cap_rights_addrspace_t
cap_rights_addrspace_intersection(cap_rights_addrspace_t b1,
				  cap_rights_addrspace_t b2)
{
	return (cap_rights_addrspace_t){ .bf = {
						 b1.bf[0] & b2.bf[0],
					 } };
}

cap_rights_addrspace_t
cap_rights_addrspace_inverse(cap_rights_addrspace_t b)
{
	return (cap_rights_addrspace_t){ .bf = {
						 ~b.bf[0],
					 } };
}

cap_rights_addrspace_t
cap_rights_addrspace_difference(cap_rights_addrspace_t b1,
				cap_rights_addrspace_t b2)
{
	cap_rights_addrspace_t not_b2 = cap_rights_addrspace_inverse(b2);
	return cap_rights_addrspace_intersection(b1, not_b2);
}

cap_rights_addrspace_t
cap_rights_addrspace_atomic_union(_Atomic cap_rights_addrspace_t *b1,
				  cap_rights_addrspace_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_addrspace_t *)b1)->bf[0];
	return (cap_rights_addrspace_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_addrspace_t
cap_rights_addrspace_atomic_intersection(_Atomic cap_rights_addrspace_t *b1,
					 cap_rights_addrspace_t		 b2,
					 memory_order			 order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_addrspace_t *)b1)->bf[0];
	return (cap_rights_addrspace_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_addrspace_t
cap_rights_addrspace_atomic_difference(_Atomic cap_rights_addrspace_t *b1,
				       cap_rights_addrspace_t	       b2,
				       memory_order		       order)
{
	cap_rights_addrspace_t not_b2 = cap_rights_addrspace_inverse(b2);
	return cap_rights_addrspace_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_addrspace_set_attach(cap_rights_addrspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_addrspace_get_attach(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_attach(cap_rights_addrspace_t	      *bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_addrspace_set_map(cap_rights_addrspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_addrspace_get_map(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_map(cap_rights_addrspace_t	   *bit_field_dst,
			      const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_addrspace_set_lookup(cap_rights_addrspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_addrspace_get_lookup(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_lookup(cap_rights_addrspace_t	      *bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_addrspace_set_add_vmmio_range(cap_rights_addrspace_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_addrspace_get_add_vmmio_range(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_add_vmmio_range(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_addrspace_set_object_activate(cap_rights_addrspace_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_addrspace_get_object_activate(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_object_activate(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_cspace_init(cap_rights_cspace_t *bit_field)
{
	*bit_field = cap_rights_cspace_default();
}

uint32_t
cap_rights_cspace_raw(cap_rights_cspace_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_cspace_atomic_ptr_raw(_Atomic cap_rights_cspace_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_cspace_t *)ptr)->bf[0];
}

cap_rights_cspace_t
cap_rights_cspace_clean(cap_rights_cspace_t bit_field)
{
	return (cap_rights_cspace_t){ .bf = {
					      (bit_field.bf[0] & 0x8000001fU),
				      } };
}

bool
cap_rights_cspace_is_equal(cap_rights_cspace_t b1, cap_rights_cspace_t b2)
{
	return ((b1.bf[0] & 0x8000001fU) == (b2.bf[0] & 0x8000001fU));
}

bool
cap_rights_cspace_is_empty(cap_rights_cspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000001fU) == 0U);
}

bool
cap_rights_cspace_is_clean(cap_rights_cspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffe0U) == 0x0U);
}

cap_rights_cspace_t
cap_rights_cspace_union(cap_rights_cspace_t b1, cap_rights_cspace_t b2)
{
	return (cap_rights_cspace_t){ .bf = {
					      b1.bf[0] | b2.bf[0],
				      } };
}

cap_rights_cspace_t
cap_rights_cspace_intersection(cap_rights_cspace_t b1, cap_rights_cspace_t b2)
{
	return (cap_rights_cspace_t){ .bf = {
					      b1.bf[0] & b2.bf[0],
				      } };
}

cap_rights_cspace_t
cap_rights_cspace_inverse(cap_rights_cspace_t b)
{
	return (cap_rights_cspace_t){ .bf = {
					      ~b.bf[0],
				      } };
}

cap_rights_cspace_t
cap_rights_cspace_difference(cap_rights_cspace_t b1, cap_rights_cspace_t b2)
{
	cap_rights_cspace_t not_b2 = cap_rights_cspace_inverse(b2);
	return cap_rights_cspace_intersection(b1, not_b2);
}

cap_rights_cspace_t
cap_rights_cspace_atomic_union(_Atomic cap_rights_cspace_t *b1,
			       cap_rights_cspace_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_cspace_t *)b1)->bf[0];
	return (cap_rights_cspace_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_cspace_t
cap_rights_cspace_atomic_intersection(_Atomic cap_rights_cspace_t *b1,
				      cap_rights_cspace_t	   b2,
				      memory_order		   order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_cspace_t *)b1)->bf[0];
	return (cap_rights_cspace_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_cspace_t
cap_rights_cspace_atomic_difference(_Atomic cap_rights_cspace_t *b1,
				    cap_rights_cspace_t b2, memory_order order)
{
	cap_rights_cspace_t not_b2 = cap_rights_cspace_inverse(b2);
	return cap_rights_cspace_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_cspace_set_cap_create(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_cspace_get_cap_create(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_cap_create(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_cspace_set_cap_delete(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_cspace_get_cap_delete(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_cap_delete(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_cspace_set_cap_copy(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_cspace_get_cap_copy(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_cap_copy(cap_rights_cspace_t	  *bit_field_dst,
				const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_cspace_set_attach(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_cspace_get_attach(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_attach(cap_rights_cspace_t	*bit_field_dst,
			      const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_cspace_set_cap_revoke(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_cspace_get_cap_revoke(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_cap_revoke(cap_rights_cspace_t	    *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_cspace_set_object_activate(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_cspace_get_object_activate(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_cspace_copy_object_activate(cap_rights_cspace_t	 *bit_field_dst,
				       const cap_rights_cspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_doorbell_init(cap_rights_doorbell_t *bit_field)
{
	*bit_field = cap_rights_doorbell_default();
}

uint32_t
cap_rights_doorbell_raw(cap_rights_doorbell_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_doorbell_atomic_ptr_raw(_Atomic cap_rights_doorbell_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_doorbell_t *)ptr)->bf[0];
}

cap_rights_doorbell_t
cap_rights_doorbell_clean(cap_rights_doorbell_t bit_field)
{
	return (cap_rights_doorbell_t){ .bf = {
						(bit_field.bf[0] & 0x80000007U),
					} };
}

bool
cap_rights_doorbell_is_equal(cap_rights_doorbell_t b1, cap_rights_doorbell_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_doorbell_is_empty(cap_rights_doorbell_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_doorbell_is_clean(cap_rights_doorbell_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
}

cap_rights_doorbell_t
cap_rights_doorbell_union(cap_rights_doorbell_t b1, cap_rights_doorbell_t b2)
{
	return (cap_rights_doorbell_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

cap_rights_doorbell_t
cap_rights_doorbell_intersection(cap_rights_doorbell_t b1,
				 cap_rights_doorbell_t b2)
{
	return (cap_rights_doorbell_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

cap_rights_doorbell_t
cap_rights_doorbell_inverse(cap_rights_doorbell_t b)
{
	return (cap_rights_doorbell_t){ .bf = {
						~b.bf[0],
					} };
}

cap_rights_doorbell_t
cap_rights_doorbell_difference(cap_rights_doorbell_t b1,
			       cap_rights_doorbell_t b2)
{
	cap_rights_doorbell_t not_b2 = cap_rights_doorbell_inverse(b2);
	return cap_rights_doorbell_intersection(b1, not_b2);
}

cap_rights_doorbell_t
cap_rights_doorbell_atomic_union(_Atomic cap_rights_doorbell_t *b1,
				 cap_rights_doorbell_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_doorbell_t *)b1)->bf[0];
	return (cap_rights_doorbell_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_doorbell_t
cap_rights_doorbell_atomic_intersection(_Atomic cap_rights_doorbell_t *b1,
					cap_rights_doorbell_t	       b2,
					memory_order		       order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_doorbell_t *)b1)->bf[0];
	return (cap_rights_doorbell_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_doorbell_t
cap_rights_doorbell_atomic_difference(_Atomic cap_rights_doorbell_t *b1,
				      cap_rights_doorbell_t	     b2,
				      memory_order		     order)
{
	cap_rights_doorbell_t not_b2 = cap_rights_doorbell_inverse(b2);
	return cap_rights_doorbell_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_doorbell_set_send(cap_rights_doorbell_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_doorbell_get_send(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_doorbell_copy_send(cap_rights_doorbell_t	  *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_doorbell_set_receive(cap_rights_doorbell_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_doorbell_get_receive(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_doorbell_copy_receive(cap_rights_doorbell_t	     *bit_field_dst,
				 const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_doorbell_set_bind(cap_rights_doorbell_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_doorbell_get_bind(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_doorbell_copy_bind(cap_rights_doorbell_t	  *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_doorbell_set_object_activate(cap_rights_doorbell_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_doorbell_get_object_activate(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_doorbell_copy_object_activate(
	cap_rights_doorbell_t	    *bit_field_dst,
	const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_hwirq_init(cap_rights_hwirq_t *bit_field)
{
	*bit_field = cap_rights_hwirq_default();
}

uint32_t
cap_rights_hwirq_raw(cap_rights_hwirq_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_hwirq_atomic_ptr_raw(_Atomic cap_rights_hwirq_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_hwirq_t *)ptr)->bf[0];
}

cap_rights_hwirq_t
cap_rights_hwirq_clean(cap_rights_hwirq_t bit_field)
{
	return (cap_rights_hwirq_t){ .bf = {
					     (bit_field.bf[0] & 0x80000002U),
				     } };
}

bool
cap_rights_hwirq_is_equal(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2)
{
	return ((b1.bf[0] & 0x80000002U) == (b2.bf[0] & 0x80000002U));
}

bool
cap_rights_hwirq_is_empty(cap_rights_hwirq_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000002U) == 0U);
}

bool
cap_rights_hwirq_is_clean(cap_rights_hwirq_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffdU) == 0x0U);
}

cap_rights_hwirq_t
cap_rights_hwirq_union(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2)
{
	return (cap_rights_hwirq_t){ .bf = {
					     b1.bf[0] | b2.bf[0],
				     } };
}

cap_rights_hwirq_t
cap_rights_hwirq_intersection(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2)
{
	return (cap_rights_hwirq_t){ .bf = {
					     b1.bf[0] & b2.bf[0],
				     } };
}

cap_rights_hwirq_t
cap_rights_hwirq_inverse(cap_rights_hwirq_t b)
{
	return (cap_rights_hwirq_t){ .bf = {
					     ~b.bf[0],
				     } };
}

cap_rights_hwirq_t
cap_rights_hwirq_difference(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2)
{
	cap_rights_hwirq_t not_b2 = cap_rights_hwirq_inverse(b2);
	return cap_rights_hwirq_intersection(b1, not_b2);
}

cap_rights_hwirq_t
cap_rights_hwirq_atomic_union(_Atomic cap_rights_hwirq_t *b1,
			      cap_rights_hwirq_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_hwirq_t *)b1)->bf[0];
	return (cap_rights_hwirq_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_hwirq_t
cap_rights_hwirq_atomic_intersection(_Atomic cap_rights_hwirq_t *b1,
				     cap_rights_hwirq_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_hwirq_t *)b1)->bf[0];
	return (cap_rights_hwirq_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_hwirq_t
cap_rights_hwirq_atomic_difference(_Atomic cap_rights_hwirq_t *b1,
				   cap_rights_hwirq_t b2, memory_order order)
{
	cap_rights_hwirq_t not_b2 = cap_rights_hwirq_inverse(b2);
	return cap_rights_hwirq_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_hwirq_set_bind_vic(cap_rights_hwirq_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_hwirq_get_bind_vic(const cap_rights_hwirq_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_hwirq_copy_bind_vic(cap_rights_hwirq_t	*bit_field_dst,
			       const cap_rights_hwirq_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_hwirq_set_object_activate(cap_rights_hwirq_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_hwirq_get_object_activate(const cap_rights_hwirq_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_hwirq_copy_object_activate(cap_rights_hwirq_t       *bit_field_dst,
				      const cap_rights_hwirq_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_memextent_init(cap_rights_memextent_t *bit_field)
{
	*bit_field = cap_rights_memextent_default();
}

uint32_t
cap_rights_memextent_raw(cap_rights_memextent_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_memextent_atomic_ptr_raw(_Atomic cap_rights_memextent_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_memextent_t *)ptr)->bf[0];
}

cap_rights_memextent_t
cap_rights_memextent_clean(cap_rights_memextent_t bit_field)
{
	return (cap_rights_memextent_t){ .bf = {
						 (bit_field.bf[0] & 0x8000001fU),
					 } };
}

bool
cap_rights_memextent_is_equal(cap_rights_memextent_t b1,
			      cap_rights_memextent_t b2)
{
	return ((b1.bf[0] & 0x8000001fU) == (b2.bf[0] & 0x8000001fU));
}

bool
cap_rights_memextent_is_empty(cap_rights_memextent_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000001fU) == 0U);
}

bool
cap_rights_memextent_is_clean(cap_rights_memextent_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffe0U) == 0x0U);
}

cap_rights_memextent_t
cap_rights_memextent_union(cap_rights_memextent_t b1, cap_rights_memextent_t b2)
{
	return (cap_rights_memextent_t){ .bf = {
						 b1.bf[0] | b2.bf[0],
					 } };
}

cap_rights_memextent_t
cap_rights_memextent_intersection(cap_rights_memextent_t b1,
				  cap_rights_memextent_t b2)
{
	return (cap_rights_memextent_t){ .bf = {
						 b1.bf[0] & b2.bf[0],
					 } };
}

cap_rights_memextent_t
cap_rights_memextent_inverse(cap_rights_memextent_t b)
{
	return (cap_rights_memextent_t){ .bf = {
						 ~b.bf[0],
					 } };
}

cap_rights_memextent_t
cap_rights_memextent_difference(cap_rights_memextent_t b1,
				cap_rights_memextent_t b2)
{
	cap_rights_memextent_t not_b2 = cap_rights_memextent_inverse(b2);
	return cap_rights_memextent_intersection(b1, not_b2);
}

cap_rights_memextent_t
cap_rights_memextent_atomic_union(_Atomic cap_rights_memextent_t *b1,
				  cap_rights_memextent_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_memextent_t *)b1)->bf[0];
	return (cap_rights_memextent_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_memextent_t
cap_rights_memextent_atomic_intersection(_Atomic cap_rights_memextent_t *b1,
					 cap_rights_memextent_t		 b2,
					 memory_order			 order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_memextent_t *)b1)->bf[0];
	return (cap_rights_memextent_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_memextent_t
cap_rights_memextent_atomic_difference(_Atomic cap_rights_memextent_t *b1,
				       cap_rights_memextent_t	       b2,
				       memory_order		       order)
{
	cap_rights_memextent_t not_b2 = cap_rights_memextent_inverse(b2);
	return cap_rights_memextent_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_memextent_set_map(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_memextent_get_map(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_map(cap_rights_memextent_t	   *bit_field_dst,
			      const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_memextent_set_derive(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_memextent_get_derive(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_derive(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_memextent_set_attach(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_memextent_get_attach(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_attach(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_memextent_set_lookup(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_memextent_get_lookup(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_lookup(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_memextent_set_donate(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_memextent_get_donate(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_donate(cap_rights_memextent_t	      *bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_memextent_set_object_activate(cap_rights_memextent_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_memextent_get_object_activate(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_object_activate(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_msgqueue_init(cap_rights_msgqueue_t *bit_field)
{
	*bit_field = cap_rights_msgqueue_default();
}

uint32_t
cap_rights_msgqueue_raw(cap_rights_msgqueue_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_msgqueue_atomic_ptr_raw(_Atomic cap_rights_msgqueue_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_msgqueue_t *)ptr)->bf[0];
}

cap_rights_msgqueue_t
cap_rights_msgqueue_clean(cap_rights_msgqueue_t bit_field)
{
	return (cap_rights_msgqueue_t){ .bf = {
						(bit_field.bf[0] & 0x8000000fU),
					} };
}

bool
cap_rights_msgqueue_is_equal(cap_rights_msgqueue_t b1, cap_rights_msgqueue_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
}

bool
cap_rights_msgqueue_is_empty(cap_rights_msgqueue_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000fU) == 0U);
}

bool
cap_rights_msgqueue_is_clean(cap_rights_msgqueue_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff0U) == 0x0U);
}

cap_rights_msgqueue_t
cap_rights_msgqueue_union(cap_rights_msgqueue_t b1, cap_rights_msgqueue_t b2)
{
	return (cap_rights_msgqueue_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

cap_rights_msgqueue_t
cap_rights_msgqueue_intersection(cap_rights_msgqueue_t b1,
				 cap_rights_msgqueue_t b2)
{
	return (cap_rights_msgqueue_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

cap_rights_msgqueue_t
cap_rights_msgqueue_inverse(cap_rights_msgqueue_t b)
{
	return (cap_rights_msgqueue_t){ .bf = {
						~b.bf[0],
					} };
}

cap_rights_msgqueue_t
cap_rights_msgqueue_difference(cap_rights_msgqueue_t b1,
			       cap_rights_msgqueue_t b2)
{
	cap_rights_msgqueue_t not_b2 = cap_rights_msgqueue_inverse(b2);
	return cap_rights_msgqueue_intersection(b1, not_b2);
}

cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_union(_Atomic cap_rights_msgqueue_t *b1,
				 cap_rights_msgqueue_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_msgqueue_t *)b1)->bf[0];
	return (cap_rights_msgqueue_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_intersection(_Atomic cap_rights_msgqueue_t *b1,
					cap_rights_msgqueue_t	       b2,
					memory_order		       order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_msgqueue_t *)b1)->bf[0];
	return (cap_rights_msgqueue_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_difference(_Atomic cap_rights_msgqueue_t *b1,
				      cap_rights_msgqueue_t	     b2,
				      memory_order		     order)
{
	cap_rights_msgqueue_t not_b2 = cap_rights_msgqueue_inverse(b2);
	return cap_rights_msgqueue_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_msgqueue_set_send(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_msgqueue_get_send(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_msgqueue_copy_send(cap_rights_msgqueue_t	  *bit_field_dst,
			      const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_msgqueue_set_receive(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_msgqueue_get_receive(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_msgqueue_copy_receive(cap_rights_msgqueue_t	     *bit_field_dst,
				 const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_msgqueue_set_bind_send(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_msgqueue_get_bind_send(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_msgqueue_copy_bind_send(cap_rights_msgqueue_t       *bit_field_dst,
				   const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_msgqueue_set_bind_receive(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_msgqueue_get_bind_receive(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_msgqueue_copy_bind_receive(cap_rights_msgqueue_t *bit_field_dst,
				      const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_msgqueue_set_object_activate(cap_rights_msgqueue_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_msgqueue_get_object_activate(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_msgqueue_copy_object_activate(
	cap_rights_msgqueue_t	    *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_partition_init(cap_rights_partition_t *bit_field)
{
	*bit_field = cap_rights_partition_default();
}

uint32_t
cap_rights_partition_raw(cap_rights_partition_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_partition_atomic_ptr_raw(_Atomic cap_rights_partition_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_partition_t *)ptr)->bf[0];
}

cap_rights_partition_t
cap_rights_partition_clean(cap_rights_partition_t bit_field)
{
	return (cap_rights_partition_t){ .bf = {
						 (bit_field.bf[0] & 0x80000003U),
					 } };
}

bool
cap_rights_partition_is_equal(cap_rights_partition_t b1,
			      cap_rights_partition_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_partition_is_empty(cap_rights_partition_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_partition_is_clean(cap_rights_partition_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_partition_t
cap_rights_partition_union(cap_rights_partition_t b1, cap_rights_partition_t b2)
{
	return (cap_rights_partition_t){ .bf = {
						 b1.bf[0] | b2.bf[0],
					 } };
}

cap_rights_partition_t
cap_rights_partition_intersection(cap_rights_partition_t b1,
				  cap_rights_partition_t b2)
{
	return (cap_rights_partition_t){ .bf = {
						 b1.bf[0] & b2.bf[0],
					 } };
}

cap_rights_partition_t
cap_rights_partition_inverse(cap_rights_partition_t b)
{
	return (cap_rights_partition_t){ .bf = {
						 ~b.bf[0],
					 } };
}

cap_rights_partition_t
cap_rights_partition_difference(cap_rights_partition_t b1,
				cap_rights_partition_t b2)
{
	cap_rights_partition_t not_b2 = cap_rights_partition_inverse(b2);
	return cap_rights_partition_intersection(b1, not_b2);
}

cap_rights_partition_t
cap_rights_partition_atomic_union(_Atomic cap_rights_partition_t *b1,
				  cap_rights_partition_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_partition_t *)b1)->bf[0];
	return (cap_rights_partition_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_partition_t
cap_rights_partition_atomic_intersection(_Atomic cap_rights_partition_t *b1,
					 cap_rights_partition_t		 b2,
					 memory_order			 order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_partition_t *)b1)->bf[0];
	return (cap_rights_partition_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_partition_t
cap_rights_partition_atomic_difference(_Atomic cap_rights_partition_t *b1,
				       cap_rights_partition_t	       b2,
				       memory_order		       order)
{
	cap_rights_partition_t not_b2 = cap_rights_partition_inverse(b2);
	return cap_rights_partition_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_partition_set_object_create(cap_rights_partition_t *bit_field,
				       bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_partition_get_object_create(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_partition_copy_object_create(
	cap_rights_partition_t	     *bit_field_dst,
	const cap_rights_partition_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_partition_set_donate(cap_rights_partition_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_partition_get_donate(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_partition_copy_donate(cap_rights_partition_t	      *bit_field_dst,
				 const cap_rights_partition_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_partition_set_object_activate(cap_rights_partition_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_partition_get_object_activate(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_partition_copy_object_activate(
	cap_rights_partition_t	     *bit_field_dst,
	const cap_rights_partition_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_thread_init(cap_rights_thread_t *bit_field)
{
	*bit_field = cap_rights_thread_default();
}

uint32_t
cap_rights_thread_raw(cap_rights_thread_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_thread_atomic_ptr_raw(_Atomic cap_rights_thread_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_thread_t *)ptr)->bf[0];
}

cap_rights_thread_t
cap_rights_thread_clean(cap_rights_thread_t bit_field)
{
	return (cap_rights_thread_t){ .bf = {
					      (bit_field.bf[0] & 0x800003ffU),
				      } };
}

bool
cap_rights_thread_is_equal(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	return ((b1.bf[0] & 0x800003ffU) == (b2.bf[0] & 0x800003ffU));
}

bool
cap_rights_thread_is_empty(cap_rights_thread_t bit_field)
{
	return ((bit_field.bf[0] & 0x800003ffU) == 0U);
}

bool
cap_rights_thread_is_clean(cap_rights_thread_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffc00U) == 0x0U);
}

cap_rights_thread_t
cap_rights_thread_union(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	return (cap_rights_thread_t){ .bf = {
					      b1.bf[0] | b2.bf[0],
				      } };
}

cap_rights_thread_t
cap_rights_thread_intersection(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	return (cap_rights_thread_t){ .bf = {
					      b1.bf[0] & b2.bf[0],
				      } };
}

cap_rights_thread_t
cap_rights_thread_inverse(cap_rights_thread_t b)
{
	return (cap_rights_thread_t){ .bf = {
					      ~b.bf[0],
				      } };
}

cap_rights_thread_t
cap_rights_thread_difference(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	cap_rights_thread_t not_b2 = cap_rights_thread_inverse(b2);
	return cap_rights_thread_intersection(b1, not_b2);
}

cap_rights_thread_t
cap_rights_thread_atomic_union(_Atomic cap_rights_thread_t *b1,
			       cap_rights_thread_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_thread_t *)b1)->bf[0];
	return (cap_rights_thread_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_thread_t
cap_rights_thread_atomic_intersection(_Atomic cap_rights_thread_t *b1,
				      cap_rights_thread_t	   b2,
				      memory_order		   order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_thread_t *)b1)->bf[0];
	return (cap_rights_thread_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_thread_t
cap_rights_thread_atomic_difference(_Atomic cap_rights_thread_t *b1,
				    cap_rights_thread_t b2, memory_order order)
{
	cap_rights_thread_t not_b2 = cap_rights_thread_inverse(b2);
	return cap_rights_thread_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_thread_set_yield_to(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_thread_get_yield_to(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_yield_to(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_thread_set_power(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_thread_get_power(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_power(cap_rights_thread_t       *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_thread_set_affinity(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_thread_get_affinity(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_affinity(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_thread_set_priority(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_thread_get_priority(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_priority(cap_rights_thread_t	  *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_thread_set_timeslice(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_thread_get_timeslice(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_timeslice(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_thread_set_bind_virq(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffdfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 5U;
}

bool
cap_rights_thread_get_bind_virq(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_bind_virq(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x20U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x20U;
}

void
cap_rights_thread_set_state(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffbfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 6U;
}

bool
cap_rights_thread_get_state(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_state(cap_rights_thread_t       *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x40U;
}

void
cap_rights_thread_set_lifecycle(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff7fU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 7U;
}

bool
cap_rights_thread_get_lifecycle(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_lifecycle(cap_rights_thread_t	   *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80U;
}

void
cap_rights_thread_set_write_context(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffeffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 8U;
}

bool
cap_rights_thread_get_write_context(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_write_context(cap_rights_thread_t       *bit_field_dst,
				     const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x100U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x100U;
}

void
cap_rights_thread_set_disable(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffdffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 9U;
}

bool
cap_rights_thread_get_disable(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 9U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_disable(cap_rights_thread_t	 *bit_field_dst,
			       const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x200U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x200U;
}

void
cap_rights_thread_set_object_activate(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_thread_get_object_activate(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_object_activate(cap_rights_thread_t	 *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_vic_init(cap_rights_vic_t *bit_field)
{
	*bit_field = cap_rights_vic_default();
}

uint32_t
cap_rights_vic_raw(cap_rights_vic_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_vic_atomic_ptr_raw(_Atomic cap_rights_vic_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_vic_t *)ptr)->bf[0];
}

cap_rights_vic_t
cap_rights_vic_clean(cap_rights_vic_t bit_field)
{
	return (cap_rights_vic_t){ .bf = {
					   (bit_field.bf[0] & 0x80000007U),
				   } };
}

bool
cap_rights_vic_is_equal(cap_rights_vic_t b1, cap_rights_vic_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_vic_is_empty(cap_rights_vic_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_vic_is_clean(cap_rights_vic_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
}

cap_rights_vic_t
cap_rights_vic_union(cap_rights_vic_t b1, cap_rights_vic_t b2)
{
	return (cap_rights_vic_t){ .bf = {
					   b1.bf[0] | b2.bf[0],
				   } };
}

cap_rights_vic_t
cap_rights_vic_intersection(cap_rights_vic_t b1, cap_rights_vic_t b2)
{
	return (cap_rights_vic_t){ .bf = {
					   b1.bf[0] & b2.bf[0],
				   } };
}

cap_rights_vic_t
cap_rights_vic_inverse(cap_rights_vic_t b)
{
	return (cap_rights_vic_t){ .bf = {
					   ~b.bf[0],
				   } };
}

cap_rights_vic_t
cap_rights_vic_difference(cap_rights_vic_t b1, cap_rights_vic_t b2)
{
	cap_rights_vic_t not_b2 = cap_rights_vic_inverse(b2);
	return cap_rights_vic_intersection(b1, not_b2);
}

cap_rights_vic_t
cap_rights_vic_atomic_union(_Atomic cap_rights_vic_t *b1, cap_rights_vic_t b2,
			    memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vic_t *)b1)->bf[0];
	return (cap_rights_vic_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vic_t
cap_rights_vic_atomic_intersection(_Atomic cap_rights_vic_t *b1,
				   cap_rights_vic_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vic_t *)b1)->bf[0];
	return (cap_rights_vic_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vic_t
cap_rights_vic_atomic_difference(_Atomic cap_rights_vic_t *b1,
				 cap_rights_vic_t b2, memory_order order)
{
	cap_rights_vic_t not_b2 = cap_rights_vic_inverse(b2);
	return cap_rights_vic_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_vic_set_bind_source(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vic_get_bind_source(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vic_copy_bind_source(cap_rights_vic_t       *bit_field_dst,
				const cap_rights_vic_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vic_set_attach_vcpu(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vic_get_attach_vcpu(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vic_copy_attach_vcpu(cap_rights_vic_t       *bit_field_dst,
				const cap_rights_vic_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vic_set_attach_vdevice(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_vic_get_attach_vdevice(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vic_copy_attach_vdevice(cap_rights_vic_t	  *bit_field_dst,
				   const cap_rights_vic_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_vic_set_object_activate(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vic_get_object_activate(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vic_copy_object_activate(cap_rights_vic_t	   *bit_field_dst,
				    const cap_rights_vic_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_virtio_mmio_init(cap_rights_virtio_mmio_t *bit_field)
{
	*bit_field = cap_rights_virtio_mmio_default();
}

uint32_t
cap_rights_virtio_mmio_raw(cap_rights_virtio_mmio_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_virtio_mmio_atomic_ptr_raw(_Atomic cap_rights_virtio_mmio_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_virtio_mmio_t *)ptr)->bf[0];
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_clean(cap_rights_virtio_mmio_t bit_field)
{
	return (cap_rights_virtio_mmio_t){ .bf = {
						   (bit_field.bf[0] &
						    0x8000000fU),
					   } };
}

bool
cap_rights_virtio_mmio_is_equal(cap_rights_virtio_mmio_t b1,
				cap_rights_virtio_mmio_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
}

bool
cap_rights_virtio_mmio_is_empty(cap_rights_virtio_mmio_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000fU) == 0U);
}

bool
cap_rights_virtio_mmio_is_clean(cap_rights_virtio_mmio_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff0U) == 0x0U);
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_union(cap_rights_virtio_mmio_t b1,
			     cap_rights_virtio_mmio_t b2)
{
	return (cap_rights_virtio_mmio_t){ .bf = {
						   b1.bf[0] | b2.bf[0],
					   } };
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_intersection(cap_rights_virtio_mmio_t b1,
				    cap_rights_virtio_mmio_t b2)
{
	return (cap_rights_virtio_mmio_t){ .bf = {
						   b1.bf[0] & b2.bf[0],
					   } };
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_inverse(cap_rights_virtio_mmio_t b)
{
	return (cap_rights_virtio_mmio_t){ .bf = {
						   ~b.bf[0],
					   } };
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_difference(cap_rights_virtio_mmio_t b1,
				  cap_rights_virtio_mmio_t b2)
{
	cap_rights_virtio_mmio_t not_b2 = cap_rights_virtio_mmio_inverse(b2);
	return cap_rights_virtio_mmio_intersection(b1, not_b2);
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_atomic_union(_Atomic cap_rights_virtio_mmio_t *b1,
				    cap_rights_virtio_mmio_t	      b2,
				    memory_order		      order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_virtio_mmio_t *)b1)->bf[0];
	return (cap_rights_virtio_mmio_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_atomic_intersection(_Atomic cap_rights_virtio_mmio_t *b1,
					   cap_rights_virtio_mmio_t	     b2,
					   memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_virtio_mmio_t *)b1)->bf[0];
	return (cap_rights_virtio_mmio_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_virtio_mmio_t
cap_rights_virtio_mmio_atomic_difference(_Atomic cap_rights_virtio_mmio_t *b1,
					 cap_rights_virtio_mmio_t	   b2,
					 memory_order order)
{
	cap_rights_virtio_mmio_t not_b2 = cap_rights_virtio_mmio_inverse(b2);
	return cap_rights_virtio_mmio_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_virtio_mmio_set_bind_backend_virq(
	cap_rights_virtio_mmio_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_virtio_mmio_get_bind_backend_virq(
	const cap_rights_virtio_mmio_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_mmio_copy_bind_backend_virq(
	cap_rights_virtio_mmio_t       *bit_field_dst,
	const cap_rights_virtio_mmio_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_virtio_mmio_set_bind_frontend_virq(
	cap_rights_virtio_mmio_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_virtio_mmio_get_bind_frontend_virq(
	const cap_rights_virtio_mmio_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_mmio_copy_bind_frontend_virq(
	cap_rights_virtio_mmio_t       *bit_field_dst,
	const cap_rights_virtio_mmio_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_virtio_mmio_set_assert_virq(cap_rights_virtio_mmio_t *bit_field,
				       bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_virtio_mmio_get_assert_virq(const cap_rights_virtio_mmio_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_mmio_copy_assert_virq(
	cap_rights_virtio_mmio_t       *bit_field_dst,
	const cap_rights_virtio_mmio_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_virtio_mmio_set_config(cap_rights_virtio_mmio_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_virtio_mmio_get_config(const cap_rights_virtio_mmio_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_mmio_copy_config(cap_rights_virtio_mmio_t *bit_field_dst,
				   const cap_rights_virtio_mmio_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_virtio_mmio_set_object_activate(cap_rights_virtio_mmio_t *bit_field,
					   bool			     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_virtio_mmio_get_object_activate(
	const cap_rights_virtio_mmio_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_mmio_copy_object_activate(
	cap_rights_virtio_mmio_t       *bit_field_dst,
	const cap_rights_virtio_mmio_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_vpm_group_init(cap_rights_vpm_group_t *bit_field)
{
	*bit_field = cap_rights_vpm_group_default();
}

uint32_t
cap_rights_vpm_group_raw(cap_rights_vpm_group_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_vpm_group_atomic_ptr_raw(_Atomic cap_rights_vpm_group_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_vpm_group_t *)ptr)->bf[0];
}

cap_rights_vpm_group_t
cap_rights_vpm_group_clean(cap_rights_vpm_group_t bit_field)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 (bit_field.bf[0] & 0x80000007U),
					 } };
}

bool
cap_rights_vpm_group_is_equal(cap_rights_vpm_group_t b1,
			      cap_rights_vpm_group_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_vpm_group_is_empty(cap_rights_vpm_group_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_vpm_group_is_clean(cap_rights_vpm_group_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
}

cap_rights_vpm_group_t
cap_rights_vpm_group_union(cap_rights_vpm_group_t b1, cap_rights_vpm_group_t b2)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 b1.bf[0] | b2.bf[0],
					 } };
}

cap_rights_vpm_group_t
cap_rights_vpm_group_intersection(cap_rights_vpm_group_t b1,
				  cap_rights_vpm_group_t b2)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 b1.bf[0] & b2.bf[0],
					 } };
}

cap_rights_vpm_group_t
cap_rights_vpm_group_inverse(cap_rights_vpm_group_t b)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 ~b.bf[0],
					 } };
}

cap_rights_vpm_group_t
cap_rights_vpm_group_difference(cap_rights_vpm_group_t b1,
				cap_rights_vpm_group_t b2)
{
	cap_rights_vpm_group_t not_b2 = cap_rights_vpm_group_inverse(b2);
	return cap_rights_vpm_group_intersection(b1, not_b2);
}

cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_union(_Atomic cap_rights_vpm_group_t *b1,
				  cap_rights_vpm_group_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vpm_group_t *)b1)->bf[0];
	return (cap_rights_vpm_group_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_intersection(_Atomic cap_rights_vpm_group_t *b1,
					 cap_rights_vpm_group_t		 b2,
					 memory_order			 order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vpm_group_t *)b1)->bf[0];
	return (cap_rights_vpm_group_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_difference(_Atomic cap_rights_vpm_group_t *b1,
				       cap_rights_vpm_group_t	       b2,
				       memory_order		       order)
{
	cap_rights_vpm_group_t not_b2 = cap_rights_vpm_group_inverse(b2);
	return cap_rights_vpm_group_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_vpm_group_set_attach_vcpu(cap_rights_vpm_group_t *bit_field,
				     bool		     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vpm_group_get_attach_vcpu(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_attach_vcpu(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vpm_group_set_bind_virq(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vpm_group_get_bind_virq(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_bind_virq(cap_rights_vpm_group_t	 *bit_field_dst,
				    const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vpm_group_set_query(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_vpm_group_get_query(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_query(cap_rights_vpm_group_t	     *bit_field_dst,
				const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_vpm_group_set_object_activate(cap_rights_vpm_group_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vpm_group_get_object_activate(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_object_activate(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_vrtc_init(cap_rights_vrtc_t *bit_field)
{
	*bit_field = cap_rights_vrtc_default();
}

uint32_t
cap_rights_vrtc_raw(cap_rights_vrtc_t bit_field)
{
	return bit_field.bf[0];
}

_Atomic uint32_t *
cap_rights_vrtc_atomic_ptr_raw(_Atomic cap_rights_vrtc_t *ptr)
{
	return (_Atomic uint32_t *)&((cap_rights_vrtc_t *)ptr)->bf[0];
}

cap_rights_vrtc_t
cap_rights_vrtc_clean(cap_rights_vrtc_t bit_field)
{
	return (cap_rights_vrtc_t){ .bf = {
					    (bit_field.bf[0] & 0x80000007U),
				    } };
}

bool
cap_rights_vrtc_is_equal(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_vrtc_is_empty(cap_rights_vrtc_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_vrtc_is_clean(cap_rights_vrtc_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
}

cap_rights_vrtc_t
cap_rights_vrtc_union(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2)
{
	return (cap_rights_vrtc_t){ .bf = {
					    b1.bf[0] | b2.bf[0],
				    } };
}

cap_rights_vrtc_t
cap_rights_vrtc_intersection(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2)
{
	return (cap_rights_vrtc_t){ .bf = {
					    b1.bf[0] & b2.bf[0],
				    } };
}

cap_rights_vrtc_t
cap_rights_vrtc_inverse(cap_rights_vrtc_t b)
{
	return (cap_rights_vrtc_t){ .bf = {
					    ~b.bf[0],
				    } };
}

cap_rights_vrtc_t
cap_rights_vrtc_difference(cap_rights_vrtc_t b1, cap_rights_vrtc_t b2)
{
	cap_rights_vrtc_t not_b2 = cap_rights_vrtc_inverse(b2);
	return cap_rights_vrtc_intersection(b1, not_b2);
}

cap_rights_vrtc_t
cap_rights_vrtc_atomic_union(_Atomic cap_rights_vrtc_t *b1,
			     cap_rights_vrtc_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vrtc_t *)b1)->bf[0];
	return (cap_rights_vrtc_t){
		.bf = { atomic_fetch_or_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vrtc_t
cap_rights_vrtc_atomic_intersection(_Atomic cap_rights_vrtc_t *b1,
				    cap_rights_vrtc_t b2, memory_order order)
{
	_Atomic uint32_t *bf =
		(_Atomic uint32_t *)&((cap_rights_vrtc_t *)b1)->bf[0];
	return (cap_rights_vrtc_t){
		.bf = { atomic_fetch_and_explicit(bf, b2.bf[0], order) }
	};
}

cap_rights_vrtc_t
cap_rights_vrtc_atomic_difference(_Atomic cap_rights_vrtc_t *b1,
				  cap_rights_vrtc_t b2, memory_order order)
{
	cap_rights_vrtc_t not_b2 = cap_rights_vrtc_inverse(b2);
	return cap_rights_vrtc_atomic_intersection(b1, not_b2, order);
}

void
cap_rights_vrtc_set_configure(cap_rights_vrtc_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vrtc_get_configure(const cap_rights_vrtc_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vrtc_copy_configure(cap_rights_vrtc_t       *bit_field_dst,
			       const cap_rights_vrtc_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vrtc_set_attach_addrspace(cap_rights_vrtc_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vrtc_get_attach_addrspace(const cap_rights_vrtc_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vrtc_copy_attach_addrspace(cap_rights_vrtc_t	      *bit_field_dst,
				      const cap_rights_vrtc_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vrtc_set_set_time_base(cap_rights_vrtc_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_vrtc_get_set_time_base(const cap_rights_vrtc_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vrtc_copy_set_time_base(cap_rights_vrtc_t	   *bit_field_dst,
				   const cap_rights_vrtc_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_vrtc_set_object_activate(cap_rights_vrtc_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vrtc_get_object_activate(const cap_rights_vrtc_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vrtc_copy_object_activate(cap_rights_vrtc_t	     *bit_field_dst,
				     const cap_rights_vrtc_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}
