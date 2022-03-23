// Automatically generated. Do not modify.
//
// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

// Bitfield Accessors

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
hyp_api_info_clean(hyp_api_info_t val)
{
	return (hyp_api_info_t){ .bf = {
					 val.bf[0] & 0xff0000000000ffffU,
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
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x3fffU) << 0U;
	return (uint16_t)val;
}

bool
hyp_api_info_get_big_endian(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 14U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_info_get_is_64bit(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 15U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

hyp_variant_t
hyp_api_info_get_variant(const hyp_api_info_t *bit_field)
{
	uint64_t	val = 0U;
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
hyp_api_flags0_clean(hyp_api_flags0_t val)
{
	return (hyp_api_flags0_t){ .bf = {
					   val.bf[0] & 0xffffffffffffffffU,
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
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_virtio_mmio(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 9U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

scheduler_variant_t
hyp_api_flags0_get_scheduler(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 28U) & (uint64_t)0xfU) << 0U;
	return (scheduler_variant_t)val;
}

uint64_t
hyp_api_flags0_get_res0_0(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 11U) & (uint64_t)0x1ffffU) << 0U;
	val |= ((bf[0] >> 32U) & (uint64_t)0xffffffffU) << 17U;
	return (uint64_t)val;
}

bool
hyp_api_flags0_get_doorbell(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_msgqueue(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_partition_cspace(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_trace_ctrl(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_vic(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_vpm(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_memextent(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_prng(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 10U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

bool
hyp_api_flags0_get_vcpu(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
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
hyp_api_flags1_clean(hyp_api_flags1_t val)
{
	return (hyp_api_flags1_t){ .bf = {
					   val.bf[0] & 0xffffffffffffffffU,
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
	uint64_t	val = 0U;
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
hyp_api_flags2_clean(hyp_api_flags2_t val)
{
	return (hyp_api_flags2_t){ .bf = {
					   val.bf[0] & 0xffffffffffffffffU,
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
	uint64_t	val = 0U;
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
memextent_attrs_clean(memextent_attrs_t val)
{
	return (memextent_attrs_t){ .bf = {
					    val.bf[0] & 0xffffffffU,
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_attrs_get_access(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_attrs_copy_access(memextent_attrs_t	      *bit_field_dst,
			    const memextent_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_attrs_set_memtype(memextent_attrs_t  *bit_field,
			    memextent_memtype_t val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffcffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x3U) << 8U;
}

memextent_memtype_t
memextent_attrs_get_memtype(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0x3U) << 0U;
	return (memextent_memtype_t)val;
}

void
memextent_attrs_copy_memtype(memextent_attrs_t       *bit_field_dst,
			     const memextent_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x300U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x300U;
}

void
memextent_attrs_set_append(memextent_attrs_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
memextent_attrs_get_append(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
memextent_attrs_copy_append(memextent_attrs_t	      *bit_field_dst,
			    const memextent_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1fU) << 0U;
	val |= ((bf[0] >> 10U) & (uint32_t)0x1fffffU) << 5U;
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
memextent_mapping_attrs_clean(memextent_mapping_attrs_t val)
{
	return (memextent_mapping_attrs_t){ .bf = {
						    val.bf[0] & 0xffffffffU,
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_mapping_attrs_get_user_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_mapping_attrs_copy_user_access(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_mapping_attrs_set_kernel_access(memextent_mapping_attrs_t *bit_field,
					  pgtable_access_t	     val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffffff8fU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x7U) << 4U;
}

pgtable_access_t
memextent_mapping_attrs_get_kernel_access(
	const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_mapping_attrs_copy_kernel_access(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x70U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x70U;
}

void
memextent_mapping_attrs_set_memtype(memextent_mapping_attrs_t *bit_field,
				    pgtable_vm_memtype_t       val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xff00ffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0xffU) << 16U;
}

pgtable_vm_memtype_t
memextent_mapping_attrs_get_memtype(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint32_t)0xffU) << 0U;
	return (pgtable_vm_memtype_t)val;
}

void
memextent_mapping_attrs_copy_memtype(
	memextent_mapping_attrs_t	  *bit_field_dst,
	const memextent_mapping_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xff0000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xff0000U;
}

uint64_t
memextent_mapping_attrs_get_res_0(const memextent_mapping_attrs_t *bit_field)
{
	uint32_t	val = 0U;
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
memextent_access_attrs_clean(memextent_access_attrs_t val)
{
	return (memextent_access_attrs_t){ .bf = {
						   val.bf[0] & 0xffffffffU,
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff8U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x7U) << 0U;
}

pgtable_access_t
memextent_access_attrs_get_user_access(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_access_attrs_copy_user_access(
	memextent_access_attrs_t	 *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x7U;
}

void
memextent_access_attrs_set_kernel_access(memextent_access_attrs_t *bit_field,
					 pgtable_access_t	   val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffffff8fU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x7U) << 4U;
}

pgtable_access_t
memextent_access_attrs_get_kernel_access(
	const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x7U) << 0U;
	return (pgtable_access_t)val;
}

void
memextent_access_attrs_copy_kernel_access(
	memextent_access_attrs_t	 *bit_field_dst,
	const memextent_access_attrs_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x70U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x70U;
}

uint64_t
memextent_access_attrs_get_res_0(const memextent_access_attrs_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	val |= ((bf[0] >> 7U) & (uint32_t)0x1ffffffU) << 1U;
	return (uint64_t)val;
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
scheduler_yield_control_clean(scheduler_yield_control_t val)
{
	return (scheduler_yield_control_t){ .bf = {
						    val.bf[0] & 0x8000ffffU,
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffff0000U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0xffffU) << 0U;
}

scheduler_yield_hint_t
scheduler_yield_control_get_hint(const scheduler_yield_control_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffffU) << 0U;
	return (scheduler_yield_hint_t)val;
}

void
scheduler_yield_control_copy_hint(scheduler_yield_control_t *bit_field_dst,
				  const scheduler_yield_control_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffffU;
}

void
scheduler_yield_control_set_impl_def(scheduler_yield_control_t *bit_field,
				     bool			val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
scheduler_yield_control_get_impl_def(const scheduler_yield_control_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
scheduler_yield_control_copy_impl_def(
	scheduler_yield_control_t	  *bit_field_dst,
	const scheduler_yield_control_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
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
vic_option_flags_clean(vic_option_flags_t val)
{
	return (vic_option_flags_t){ .bf = {
					     val.bf[0] & 0xffffffffffffffffU,
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
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vic_option_flags_get_max_msis_valid(const vic_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vic_option_flags_copy_max_msis_valid(vic_option_flags_t	*bit_field_dst,
				     const vic_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vic_option_flags_set_res0_0(vic_option_flags_t *bit_field, uint64_t val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0x1U;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x7fffffffffffffffU)
		 << 1U;
}

uint64_t
vic_option_flags_get_res0_0(const vic_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x7fffffffffffffffU) << 0U;
	return (uint64_t)val;
}

void
vic_option_flags_copy_res0_0(vic_option_flags_t	*bit_field_dst,
			     const vic_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xfffffffffffffffeU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xfffffffffffffffeU;
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
msgqueue_create_info_clean(msgqueue_create_info_t val)
{
	return (msgqueue_create_info_t){ .bf = {
						 val.bf[0] & 0xffffffffU,
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
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xffffffffffff0000U;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0xffffU) << 0U;
}

uint16_t
msgqueue_create_info_get_queue_depth(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffU) << 0U;
	return (uint16_t)val;
}

void
msgqueue_create_info_copy_queue_depth(
	msgqueue_create_info_t       *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffU;
}

void
msgqueue_create_info_set_max_msg_size(msgqueue_create_info_t *bit_field,
				      uint16_t		      val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xffffffff0000ffffU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0xffffU) << 16U;
}

uint16_t
msgqueue_create_info_get_max_msg_size(const msgqueue_create_info_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0xffffU) << 0U;
	return (uint16_t)val;
}

void
msgqueue_create_info_copy_max_msg_size(
	msgqueue_create_info_t       *bit_field_dst,
	const msgqueue_create_info_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
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
msgqueue_send_flags_clean(msgqueue_send_flags_t val)
{
	return (msgqueue_send_flags_t){ .bf = {
						val.bf[0] & 0x1U,
					} };
}

bool
msgqueue_send_flags_is_equal(msgqueue_send_flags_t b1, msgqueue_send_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
msgqueue_send_flags_get_push(const msgqueue_send_flags_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
msgqueue_send_flags_copy_push(msgqueue_send_flags_t	    *bit_field_dst,
			      const msgqueue_send_flags_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
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
vcpu_option_flags_clean(vcpu_option_flags_t val)
{
	return (vcpu_option_flags_t){ .bf = {
					      val.bf[0] & 0x800000000000001fU,
				      } };
}

bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return ((b1.bf[0] & 0x800000000000001fU) ==
		(b2.bf[0] & 0x800000000000001fU));
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
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vcpu_option_flags_get_pinned(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_pinned(vcpu_option_flags_t	  *bit_field_dst,
			      const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
vcpu_option_flags_set_ras_error_handler(vcpu_option_flags_t *bit_field,
					bool		     val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vcpu_option_flags_get_ras_error_handler(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_ras_error_handler(
	vcpu_option_flags_t	    *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
vcpu_option_flags_set_amu_counting_disabled(vcpu_option_flags_t *bit_field,
					    bool		 val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xfffffffffffffffbU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 2U;
}

bool
vcpu_option_flags_get_amu_counting_disabled(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_amu_counting_disabled(
	vcpu_option_flags_t	    *bit_field_dst,
	const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x4U;
}

void
vcpu_option_flags_set_sve_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
vcpu_option_flags_get_sve_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_sve_allowed(vcpu_option_flags_t       *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
vcpu_option_flags_set_hlos_vm(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0x7fffffffffffffffU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 63U;
}

bool
vcpu_option_flags_get_hlos_vm(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 63U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_hlos_vm(vcpu_option_flags_t	   *bit_field_dst,
			       const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8000000000000000U;
}

void
vcpu_option_flags_set_debug_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t *bf = (uint64_t *)bit_field;
	bf[0] &= (uint64_t)0xffffffffffffffefU;
	bf[0] |= ((((uint64_t)val) >> 0U) & (uint64_t)0x1U) << 4U;
}

bool
vcpu_option_flags_get_debug_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0U;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return (bool)val;
}

void
vcpu_option_flags_copy_debug_allowed(vcpu_option_flags_t	 *bit_field_dst,
				     const vcpu_option_flags_t *bit_field_src)
{
	uint64_t	 *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x10U;
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
cap_rights_generic_clean(cap_rights_generic_t val)
{
	return (cap_rights_generic_t){ .bf = {
					       val.bf[0] & 0x80000000U,
				       } };
}

bool
cap_rights_generic_is_equal(cap_rights_generic_t b1, cap_rights_generic_t b2)
{
	return ((b1.bf[0] & 0x80000000U) == (b2.bf[0] & 0x80000000U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_generic_get_object_activate(const cap_rights_generic_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_generic_copy_object_activate(
	cap_rights_generic_t	     *bit_field_dst,
	const cap_rights_generic_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_addrspace_clean(cap_rights_addrspace_t val)
{
	return (cap_rights_addrspace_t){ .bf = {
						 val.bf[0] & 0x80000003U,
					 } };
}

bool
cap_rights_addrspace_is_equal(cap_rights_addrspace_t b1,
			      cap_rights_addrspace_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_addrspace_get_attach(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_addrspace_copy_attach(cap_rights_addrspace_t	*bit_field_dst,
				 const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_addrspace_set_map(cap_rights_addrspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_addrspace_get_map(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_addrspace_copy_map(cap_rights_addrspace_t	     *bit_field_dst,
			      const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_addrspace_set_object_activate(cap_rights_addrspace_t *bit_field,
					 bool			 val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_addrspace_get_object_activate(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_addrspace_copy_object_activate(
	cap_rights_addrspace_t       *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_cspace_clean(cap_rights_cspace_t val)
{
	return (cap_rights_cspace_t){ .bf = {
					      val.bf[0] & 0x8000001fU,
				      } };
}

bool
cap_rights_cspace_is_equal(cap_rights_cspace_t b1, cap_rights_cspace_t b2)
{
	return ((b1.bf[0] & 0x8000001fU) == (b2.bf[0] & 0x8000001fU));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_cspace_get_cap_create(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_cap_create(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_cspace_set_cap_delete(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_cspace_get_cap_delete(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_cap_delete(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_cspace_set_cap_copy(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_cspace_get_cap_copy(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_cap_copy(cap_rights_cspace_t	    *bit_field_dst,
				const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_cspace_set_attach(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_cspace_get_attach(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_attach(cap_rights_cspace_t	  *bit_field_dst,
			      const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_cspace_set_cap_revoke(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_cspace_get_cap_revoke(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_cap_revoke(cap_rights_cspace_t	      *bit_field_dst,
				  const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_cspace_set_object_activate(cap_rights_cspace_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_cspace_get_object_activate(const cap_rights_cspace_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_cspace_copy_object_activate(cap_rights_cspace_t	   *bit_field_dst,
				       const cap_rights_cspace_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_doorbell_clean(cap_rights_doorbell_t val)
{
	return (cap_rights_doorbell_t){ .bf = {
						val.bf[0] & 0x80000007U,
					} };
}

bool
cap_rights_doorbell_is_equal(cap_rights_doorbell_t b1, cap_rights_doorbell_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_doorbell_get_send(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_doorbell_copy_send(cap_rights_doorbell_t	    *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_doorbell_set_receive(cap_rights_doorbell_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_doorbell_get_receive(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_doorbell_copy_receive(cap_rights_doorbell_t       *bit_field_dst,
				 const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_doorbell_set_bind(cap_rights_doorbell_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_doorbell_get_bind(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_doorbell_copy_bind(cap_rights_doorbell_t	    *bit_field_dst,
			      const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_doorbell_set_object_activate(cap_rights_doorbell_t *bit_field,
					bool		       val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_doorbell_get_object_activate(const cap_rights_doorbell_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_doorbell_copy_object_activate(
	cap_rights_doorbell_t	      *bit_field_dst,
	const cap_rights_doorbell_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_hwirq_clean(cap_rights_hwirq_t val)
{
	return (cap_rights_hwirq_t){ .bf = {
					     val.bf[0] & 0x80000002U,
				     } };
}

bool
cap_rights_hwirq_is_equal(cap_rights_hwirq_t b1, cap_rights_hwirq_t b2)
{
	return ((b1.bf[0] & 0x80000002U) == (b2.bf[0] & 0x80000002U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_hwirq_get_bind_vic(const cap_rights_hwirq_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_hwirq_copy_bind_vic(cap_rights_hwirq_t	  *bit_field_dst,
			       const cap_rights_hwirq_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_hwirq_set_object_activate(cap_rights_hwirq_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_hwirq_get_object_activate(const cap_rights_hwirq_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_hwirq_copy_object_activate(cap_rights_hwirq_t	 *bit_field_dst,
				      const cap_rights_hwirq_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_memextent_clean(cap_rights_memextent_t val)
{
	return (cap_rights_memextent_t){ .bf = {
						 val.bf[0] & 0x80000007U,
					 } };
}

bool
cap_rights_memextent_is_equal(cap_rights_memextent_t b1,
			      cap_rights_memextent_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_memextent_get_map(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_memextent_copy_map(cap_rights_memextent_t	     *bit_field_dst,
			      const cap_rights_memextent_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_memextent_set_derive(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_memextent_get_derive(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_memextent_copy_derive(cap_rights_memextent_t	*bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_memextent_set_attach(cap_rights_memextent_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_memextent_get_attach(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_memextent_copy_attach(cap_rights_memextent_t	*bit_field_dst,
				 const cap_rights_memextent_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_memextent_set_object_activate(cap_rights_memextent_t *bit_field,
					 bool			 val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_memextent_get_object_activate(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_memextent_copy_object_activate(
	cap_rights_memextent_t       *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_msgqueue_clean(cap_rights_msgqueue_t val)
{
	return (cap_rights_msgqueue_t){ .bf = {
						val.bf[0] & 0x8000000fU,
					} };
}

bool
cap_rights_msgqueue_is_equal(cap_rights_msgqueue_t b1, cap_rights_msgqueue_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_msgqueue_get_send(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_msgqueue_copy_send(cap_rights_msgqueue_t	    *bit_field_dst,
			      const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_msgqueue_set_receive(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_msgqueue_get_receive(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_msgqueue_copy_receive(cap_rights_msgqueue_t       *bit_field_dst,
				 const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_msgqueue_set_bind_send(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_msgqueue_get_bind_send(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_msgqueue_copy_bind_send(cap_rights_msgqueue_t	 *bit_field_dst,
				   const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_msgqueue_set_bind_receive(cap_rights_msgqueue_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_msgqueue_get_bind_receive(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_msgqueue_copy_bind_receive(cap_rights_msgqueue_t *bit_field_dst,
				      const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_msgqueue_set_object_activate(cap_rights_msgqueue_t *bit_field,
					bool		       val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_msgqueue_get_object_activate(const cap_rights_msgqueue_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_msgqueue_copy_object_activate(
	cap_rights_msgqueue_t	      *bit_field_dst,
	const cap_rights_msgqueue_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_partition_clean(cap_rights_partition_t val)
{
	return (cap_rights_partition_t){ .bf = {
						 val.bf[0] & 0x80000001U,
					 } };
}

bool
cap_rights_partition_is_equal(cap_rights_partition_t b1,
			      cap_rights_partition_t b2)
{
	return ((b1.bf[0] & 0x80000001U) == (b2.bf[0] & 0x80000001U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_partition_get_object_create(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_partition_copy_object_create(
	cap_rights_partition_t       *bit_field_dst,
	const cap_rights_partition_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_partition_set_object_activate(cap_rights_partition_t *bit_field,
					 bool			 val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_partition_get_object_activate(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_partition_copy_object_activate(
	cap_rights_partition_t       *bit_field_dst,
	const cap_rights_partition_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_thread_clean(cap_rights_thread_t val)
{
	return (cap_rights_thread_t){ .bf = {
					      val.bf[0] & 0x8000009fU,
				      } };
}

bool
cap_rights_thread_is_equal(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	return ((b1.bf[0] & 0x8000009fU) == (b2.bf[0] & 0x8000009fU));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_thread_get_yield_to(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_yield_to(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_thread_set_power(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_thread_get_power(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_power(cap_rights_thread_t	 *bit_field_dst,
			     const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_thread_set_affinity(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_thread_get_affinity(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_affinity(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_thread_set_priority(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_thread_get_priority(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_priority(cap_rights_thread_t	    *bit_field_dst,
				const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_thread_set_timeslice(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_thread_get_timeslice(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_timeslice(cap_rights_thread_t	     *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_thread_set_lifecycle(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xffffff7fU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 7U;
}

bool
cap_rights_thread_get_lifecycle(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_lifecycle(cap_rights_thread_t	     *bit_field_dst,
				 const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80U;
}

void
cap_rights_thread_set_object_activate(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_thread_get_object_activate(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_thread_copy_object_activate(cap_rights_thread_t	   *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_vic_clean(cap_rights_vic_t val)
{
	return (cap_rights_vic_t){ .bf = {
					   val.bf[0] & 0x80000003U,
				   } };
}

bool
cap_rights_vic_is_equal(cap_rights_vic_t b1, cap_rights_vic_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vic_get_bind_source(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vic_copy_bind_source(cap_rights_vic_t	 *bit_field_dst,
				const cap_rights_vic_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vic_set_attach_vcpu(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vic_get_attach_vcpu(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vic_copy_attach_vcpu(cap_rights_vic_t	 *bit_field_dst,
				const cap_rights_vic_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vic_set_object_activate(cap_rights_vic_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vic_get_object_activate(const cap_rights_vic_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vic_copy_object_activate(cap_rights_vic_t	     *bit_field_dst,
				    const cap_rights_vic_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
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
cap_rights_vpm_group_clean(cap_rights_vpm_group_t val)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 val.bf[0] & 0x80000007U,
					 } };
}

bool
cap_rights_vpm_group_is_equal(cap_rights_vpm_group_t b1,
			      cap_rights_vpm_group_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
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
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vpm_group_get_attach_vcpu(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vpm_group_copy_attach_vcpu(
	cap_rights_vpm_group_t       *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vpm_group_set_bind_virq(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vpm_group_get_bind_virq(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vpm_group_copy_bind_virq(cap_rights_vpm_group_t	   *bit_field_dst,
				    const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vpm_group_set_query(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_vpm_group_get_query(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vpm_group_copy_query(cap_rights_vpm_group_t       *bit_field_dst,
				const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_vpm_group_set_object_activate(cap_rights_vpm_group_t *bit_field,
					 bool			 val)
{
	uint32_t *bf = (uint32_t *)bit_field;
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((((uint32_t)val) >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vpm_group_get_object_activate(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0U;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return (bool)val;
}

void
cap_rights_vpm_group_copy_object_activate(
	cap_rights_vpm_group_t       *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t	 *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}
