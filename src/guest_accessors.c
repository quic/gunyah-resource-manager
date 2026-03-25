// Automatically generated. Do not modify.
//
// Copyright © Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

// Bitfield Accessors

void
addrspace_info_area_entry_data_info_init(
	addrspace_info_area_entry_data_info_t *bit_field)
{
	*bit_field = addrspace_info_area_entry_data_info_default();
}

uint64_t
addrspace_info_area_entry_data_info_raw(
	addrspace_info_area_entry_data_info_t bit_field)
{
	return bit_field.bf[0];
}

addrspace_info_area_entry_data_info_t
addrspace_info_area_entry_data_info_clean(
	addrspace_info_area_entry_data_info_t bit_field)
{
	return (addrspace_info_area_entry_data_info_t){ .bf = {
								(bit_field.bf[0] &
								 0xffffffffffffffffU),
							} };
}

bool
addrspace_info_area_entry_data_info_is_equal(
	addrspace_info_area_entry_data_info_t b1,
	addrspace_info_area_entry_data_info_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
addrspace_info_area_entry_data_info_is_clean(
	addrspace_info_area_entry_data_info_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
addrspace_info_area_entry_data_info_set_size(
	addrspace_info_area_entry_data_info_t *bit_field, size_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffff00000000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffffffU) << 0U;
}

size_t
addrspace_info_area_entry_data_info_get_size(
	const addrspace_info_area_entry_data_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffU) << 0U;
	return (size_t)val;
}

void
addrspace_info_area_entry_data_info_copy_size(
	addrspace_info_area_entry_data_info_t	    *bit_field_dst,
	const addrspace_info_area_entry_data_info_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffffU;
}

void
addrspace_info_area_entry_data_info_set_alignment(
	addrspace_info_area_entry_data_info_t *bit_field, size_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffffffU) << 32U;
}

size_t
addrspace_info_area_entry_data_info_get_alignment(
	const addrspace_info_area_entry_data_info_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 32U) & (uint64_t)0xffffffffU) << 0U;
	return (size_t)val;
}

void
addrspace_info_area_entry_data_info_copy_alignment(
	addrspace_info_area_entry_data_info_t	    *bit_field_dst,
	const addrspace_info_area_entry_data_info_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffff00000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffff00000000U;
}

void
addrspace_info_area_entry_flags_init(
	addrspace_info_area_entry_flags_t *bit_field)
{
	*bit_field = addrspace_info_area_entry_flags_default();
}

uint32_t
addrspace_info_area_entry_flags_raw(addrspace_info_area_entry_flags_t bit_field)
{
	return bit_field.bf[0];
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_clean(
	addrspace_info_area_entry_flags_t bit_field)
{
	return (addrspace_info_area_entry_flags_t){ .bf = {
							    (bit_field.bf[0] &
							     0x80000000U),
						    } };
}

bool
addrspace_info_area_entry_flags_is_equal(addrspace_info_area_entry_flags_t b1,
					 addrspace_info_area_entry_flags_t b2)
{
	return ((b1.bf[0] & 0x80000000U) == (b2.bf[0] & 0x80000000U));
}

bool
addrspace_info_area_entry_flags_is_empty(
	addrspace_info_area_entry_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000000U) == 0U);
}

bool
addrspace_info_area_entry_flags_is_clean(
	addrspace_info_area_entry_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffffU) == 0x0U);
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_union(addrspace_info_area_entry_flags_t b1,
				      addrspace_info_area_entry_flags_t b2)
{
	return (addrspace_info_area_entry_flags_t){ .bf = {
							    b1.bf[0] | b2.bf[0],
						    } };
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_intersection(
	addrspace_info_area_entry_flags_t b1,
	addrspace_info_area_entry_flags_t b2)
{
	return (addrspace_info_area_entry_flags_t){ .bf = {
							    b1.bf[0] & b2.bf[0],
						    } };
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_inverse(addrspace_info_area_entry_flags_t b)
{
	return (addrspace_info_area_entry_flags_t){ .bf = {
							    (uint32_t)~b.bf[0],
						    } };
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_difference(addrspace_info_area_entry_flags_t b1,
					   addrspace_info_area_entry_flags_t b2)
{
	addrspace_info_area_entry_flags_t not_b2 =
		addrspace_info_area_entry_flags_inverse(b2);
	return addrspace_info_area_entry_flags_intersection(b1, not_b2);
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_union(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_info_area_entry_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_info_area_entry_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	addrspace_info_area_entry_flags_t new_value;

	do {
		new_value =
			addrspace_info_area_entry_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_intersection(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	addrspace_info_area_entry_flags_t not_b2 =
		addrspace_info_area_entry_flags_inverse(b2);
	return addrspace_info_area_entry_flags_atomic_difference(b1, not_b2,
								 order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_info_area_entry_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	addrspace_info_area_entry_flags_t new_value;

	do {
		new_value = addrspace_info_area_entry_flags_intersection(
			old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_info_area_entry_flags_t
addrspace_info_area_entry_flags_atomic_difference(
	_Atomic addrspace_info_area_entry_flags_t *b1,
	addrspace_info_area_entry_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_info_area_entry_flags_cast(ret_u);

#else
	addrspace_info_area_entry_flags_t not_b2 =
		addrspace_info_area_entry_flags_inverse(b2);
	return addrspace_info_area_entry_flags_atomic_intersection(b1, not_b2,
								   order);
#endif
}

void
addrspace_info_area_entry_flags_set_valid(
	addrspace_info_area_entry_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
addrspace_info_area_entry_flags_get_valid(
	const addrspace_info_area_entry_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_info_area_entry_flags_copy_valid(
	addrspace_info_area_entry_flags_t	*bit_field_dst,
	const addrspace_info_area_entry_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
addrspace_info_area_entry_type_init(addrspace_info_area_entry_type_t *bit_field)
{
	*bit_field = addrspace_info_area_entry_type_default();
}

uint32_t
addrspace_info_area_entry_type_raw(addrspace_info_area_entry_type_t bit_field)
{
	return bit_field.bf[0];
}

addrspace_info_area_entry_type_t
addrspace_info_area_entry_type_clean(addrspace_info_area_entry_type_t bit_field)
{
	return (addrspace_info_area_entry_type_t){ .bf = {
							   (bit_field.bf[0] &
							    0xffffffffU),
						   } };
}

bool
addrspace_info_area_entry_type_is_equal(addrspace_info_area_entry_type_t b1,
					addrspace_info_area_entry_type_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

bool
addrspace_info_area_entry_type_is_clean(
	addrspace_info_area_entry_type_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
addrspace_info_area_entry_type_set_id(
	addrspace_info_area_entry_type_t *bit_field, uint32_t val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffff0000U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffffU) << 0U;
}

uint32_t
addrspace_info_area_entry_type_get_id(
	const addrspace_info_area_entry_type_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffffU) << 0U;
	return (uint32_t)val;
}

void
addrspace_info_area_entry_type_copy_id(
	addrspace_info_area_entry_type_t       *bit_field_dst,
	const addrspace_info_area_entry_type_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffffU;
}

void
addrspace_info_area_entry_type_set_owner(
	addrspace_info_area_entry_type_t *bit_field,
	addrspace_info_area_id_owner_t	  val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffU;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffffU) << 16U;
}

addrspace_info_area_id_owner_t
addrspace_info_area_entry_type_get_owner(
	const addrspace_info_area_entry_type_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint32_t)0xffffU) << 0U;
	return (addrspace_info_area_id_owner_t)val;
}

void
addrspace_info_area_entry_type_copy_owner(
	addrspace_info_area_entry_type_t       *bit_field_dst,
	const addrspace_info_area_entry_type_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffff0000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffff0000U;
}

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

addrspace_map_flags_t
addrspace_map_flags_clean(addrspace_map_flags_t bit_field)
{
	return (addrspace_map_flags_t){ .bf = {
						(bit_field.bf[0] & 0x8000000fU),
					} };
}

bool
addrspace_map_flags_is_equal(addrspace_map_flags_t b1, addrspace_map_flags_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
}

bool
addrspace_map_flags_is_empty(addrspace_map_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000fU) == 0U);
}

bool
addrspace_map_flags_is_clean(addrspace_map_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff0U) == 0x0U);
}

addrspace_map_flags_t
addrspace_map_flags_union(addrspace_map_flags_t b1, addrspace_map_flags_t b2)
{
	return (addrspace_map_flags_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

addrspace_map_flags_t
addrspace_map_flags_intersection(addrspace_map_flags_t b1,
				 addrspace_map_flags_t b2)
{
	return (addrspace_map_flags_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

addrspace_map_flags_t
addrspace_map_flags_inverse(addrspace_map_flags_t b)
{
	return (addrspace_map_flags_t){ .bf = {
						(uint32_t)~b.bf[0],
					} };
}

addrspace_map_flags_t
addrspace_map_flags_difference(addrspace_map_flags_t b1,
			       addrspace_map_flags_t b2)
{
	addrspace_map_flags_t not_b2 = addrspace_map_flags_inverse(b2);
	return addrspace_map_flags_intersection(b1, not_b2);
}

addrspace_map_flags_t
addrspace_map_flags_atomic_union(_Atomic addrspace_map_flags_t *b1,
				 addrspace_map_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_map_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_map_flags_t old_value = atomic_load_explicit(b1, load_order);
	addrspace_map_flags_t new_value;

	do {
		new_value = addrspace_map_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_map_flags_t
addrspace_map_flags_atomic_intersection(_Atomic addrspace_map_flags_t *b1,
					addrspace_map_flags_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	addrspace_map_flags_t not_b2 = addrspace_map_flags_inverse(b2);
	return addrspace_map_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_map_flags_t old_value = atomic_load_explicit(b1, load_order);
	addrspace_map_flags_t new_value;

	do {
		new_value = addrspace_map_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_map_flags_t
addrspace_map_flags_atomic_difference(_Atomic addrspace_map_flags_t *b1,
				      addrspace_map_flags_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_map_flags_cast(ret_u);

#else
	addrspace_map_flags_t not_b2 = addrspace_map_flags_inverse(b2);
	return addrspace_map_flags_atomic_intersection(b1, not_b2, order);
#endif
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
addrspace_map_flags_set_private(addrspace_map_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
addrspace_map_flags_get_private(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_map_flags_copy_private(addrspace_map_flags_t	     *bit_field_dst,
				 const addrspace_map_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
addrspace_map_flags_set_vmmio(addrspace_map_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
addrspace_map_flags_get_vmmio(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_map_flags_copy_vmmio(addrspace_map_flags_t	   *bit_field_dst,
			       const addrspace_map_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
addrspace_map_flags_set_whole_extent(addrspace_map_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
addrspace_map_flags_get_whole_extent(const addrspace_map_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_map_flags_copy_whole_extent(addrspace_map_flags_t *bit_field_dst,
				      const addrspace_map_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
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

void
addrspace_modify_pages_flags_init(addrspace_modify_pages_flags_t *bit_field)
{
	*bit_field = addrspace_modify_pages_flags_default();
}

uint32_t
addrspace_modify_pages_flags_raw(addrspace_modify_pages_flags_t bit_field)
{
	return bit_field.bf[0];
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_clean(addrspace_modify_pages_flags_t bit_field)
{
	return (addrspace_modify_pages_flags_t){ .bf = {
							 // (0x2U & ~0xdU) |
							 (uint32_t)(0x2U) |
								 (bit_field.bf[0] &
								  0xdU),
						 } };
}

bool
addrspace_modify_pages_flags_is_equal(addrspace_modify_pages_flags_t b1,
				      addrspace_modify_pages_flags_t b2)
{
	return ((b1.bf[0] & 0xdU) == (b2.bf[0] & 0xdU));
}

bool
addrspace_modify_pages_flags_is_empty(addrspace_modify_pages_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xdU) == 0U);
}

bool
addrspace_modify_pages_flags_is_clean(addrspace_modify_pages_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffff2U) == 0x2U);
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_union(addrspace_modify_pages_flags_t b1,
				   addrspace_modify_pages_flags_t b2)
{
	return (addrspace_modify_pages_flags_t){ .bf = {
							 b1.bf[0] | b2.bf[0],
						 } };
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_intersection(addrspace_modify_pages_flags_t b1,
					  addrspace_modify_pages_flags_t b2)
{
	return (addrspace_modify_pages_flags_t){ .bf = {
							 b1.bf[0] & b2.bf[0],
						 } };
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_inverse(addrspace_modify_pages_flags_t b)
{
	return (addrspace_modify_pages_flags_t){ .bf = {
							 (uint32_t)~b.bf[0],
						 } };
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_difference(addrspace_modify_pages_flags_t b1,
					addrspace_modify_pages_flags_t b2)
{
	addrspace_modify_pages_flags_t not_b2 =
		addrspace_modify_pages_flags_inverse(b2);
	return addrspace_modify_pages_flags_intersection(b1, not_b2);
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_union(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_modify_pages_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_modify_pages_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	addrspace_modify_pages_flags_t new_value;

	do {
		new_value = addrspace_modify_pages_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_intersection(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	addrspace_modify_pages_flags_t not_b2 =
		addrspace_modify_pages_flags_inverse(b2);
	return addrspace_modify_pages_flags_atomic_difference(b1, not_b2,
							      order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	addrspace_modify_pages_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	addrspace_modify_pages_flags_t new_value;

	do {
		new_value = addrspace_modify_pages_flags_intersection(old_value,
								      b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

addrspace_modify_pages_flags_t
addrspace_modify_pages_flags_atomic_difference(
	_Atomic addrspace_modify_pages_flags_t *b1,
	addrspace_modify_pages_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return addrspace_modify_pages_flags_cast(ret_u);

#else
	addrspace_modify_pages_flags_t not_b2 =
		addrspace_modify_pages_flags_inverse(b2);
	return addrspace_modify_pages_flags_atomic_intersection(b1, not_b2,
								order);
#endif
}

void
addrspace_modify_pages_flags_set_unlock(
	addrspace_modify_pages_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
addrspace_modify_pages_flags_get_unlock(
	const addrspace_modify_pages_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_modify_pages_flags_copy_unlock(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
addrspace_modify_pages_flags_set_no_sync_unlock(
	addrspace_modify_pages_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
addrspace_modify_pages_flags_get_no_sync_unlock(
	const addrspace_modify_pages_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_modify_pages_flags_copy_no_sync_unlock(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
addrspace_modify_pages_flags_set_do_not_sanitise(
	addrspace_modify_pages_flags_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
addrspace_modify_pages_flags_get_do_not_sanitise(
	const addrspace_modify_pages_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
addrspace_modify_pages_flags_copy_do_not_sanitise(
	addrspace_modify_pages_flags_t	     *bit_field_dst,
	const addrspace_modify_pages_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
allocator_memattr_init(allocator_memattr_t *bit_field)
{
	*bit_field = allocator_memattr_default();
}

uint16_t
allocator_memattr_raw(allocator_memattr_t bit_field)
{
	return bit_field.bf[0];
}

allocator_memattr_t
allocator_memattr_clean(allocator_memattr_t bit_field)
{
	return (allocator_memattr_t){ .bf = {
					      (bit_field.bf[0] & 0xfU),
				      } };
}

bool
allocator_memattr_is_equal(allocator_memattr_t b1, allocator_memattr_t b2)
{
	return ((b1.bf[0] & 0xfU) == (b2.bf[0] & 0xfU));
}

bool
allocator_memattr_is_clean(allocator_memattr_t bit_field)
{
	return ((bit_field.bf[0] & 0xfff0U) == 0x0U);
}

void
allocator_memattr_set_type(allocator_memattr_t *bit_field,
			   allocator_memtype_t	val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0xfff0U;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0xfU) << 0U;
}

allocator_memtype_t
allocator_memattr_get_type(const allocator_memattr_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint16_t)0xfU) << 0U;
	return (allocator_memtype_t)val;
}

void
allocator_memattr_copy_type(allocator_memattr_t	      *bit_field_dst,
			    const allocator_memattr_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0xfU;
	bf_dst[0] |= bf_src[0] & (uint16_t)0xfU;
}

void
allocator_stats_info_init(allocator_stats_info_t *bit_field)
{
	*bit_field = allocator_stats_info_default();
}

uint32_t
allocator_stats_info_raw(allocator_stats_info_t bit_field)
{
	return bit_field.bf[0];
}

allocator_stats_info_t
allocator_stats_info_clean(allocator_stats_info_t bit_field)
{
	return (allocator_stats_info_t){ .bf = {
						 // (0x1U & ~0xffU) |
						 (uint32_t)(0x0U) |
							 (bit_field.bf[0] &
							  0xffU),
					 } };
}

bool
allocator_stats_info_is_equal(allocator_stats_info_t b1,
			      allocator_stats_info_t b2)
{
	return ((b1.bf[0] & 0xffU) == (b2.bf[0] & 0xffU));
}

bool
allocator_stats_info_is_clean(allocator_stats_info_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffff00U) == 0x0U);
}

uint8_t
allocator_stats_info_get_version(const allocator_stats_info_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffU) << 0U;
	return (uint8_t)val;
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

cap_rights_addrspace_t
cap_rights_addrspace_clean(cap_rights_addrspace_t bit_field)
{
	return (cap_rights_addrspace_t){ .bf = {
						 (bit_field.bf[0] & 0x8000007fU),
					 } };
}

bool
cap_rights_addrspace_is_equal(cap_rights_addrspace_t b1,
			      cap_rights_addrspace_t b2)
{
	return ((b1.bf[0] & 0x8000007fU) == (b2.bf[0] & 0x8000007fU));
}

bool
cap_rights_addrspace_is_empty(cap_rights_addrspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000007fU) == 0U);
}

bool
cap_rights_addrspace_is_clean(cap_rights_addrspace_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffff80U) == 0x0U);
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
						 (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_addrspace_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_addrspace_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_addrspace_t new_value;

	do {
		new_value = cap_rights_addrspace_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_addrspace_t
cap_rights_addrspace_atomic_intersection(_Atomic cap_rights_addrspace_t *b1,
					 cap_rights_addrspace_t		 b2,
					 memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_addrspace_t not_b2 = cap_rights_addrspace_inverse(b2);
	return cap_rights_addrspace_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_addrspace_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_addrspace_t new_value;

	do {
		new_value = cap_rights_addrspace_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_addrspace_t
cap_rights_addrspace_atomic_difference(_Atomic cap_rights_addrspace_t *b1,
				       cap_rights_addrspace_t	       b2,
				       memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_addrspace_cast(ret_u);

#else
	cap_rights_addrspace_t not_b2 = cap_rights_addrspace_inverse(b2);
	return cap_rights_addrspace_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_addrspace_set_configure_range(cap_rights_addrspace_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_addrspace_get_configure_range(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_configure_range(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_addrspace_set_map_protected(cap_rights_addrspace_t *bit_field,
				       bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_addrspace_get_map_protected(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_map_protected(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_addrspace_set_modify_protected(cap_rights_addrspace_t *bit_field,
					  bool			  val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffdfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 5U;
}

bool
cap_rights_addrspace_get_modify_protected(
	const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_modify_protected(
	cap_rights_addrspace_t	     *bit_field_dst,
	const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x20U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x20U;
}

void
cap_rights_addrspace_set_add_info(cap_rights_addrspace_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffbfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 6U;
}

bool
cap_rights_addrspace_get_add_info(const cap_rights_addrspace_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_addrspace_copy_add_info(cap_rights_addrspace_t	*bit_field_dst,
				   const cap_rights_addrspace_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x40U;
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
					      (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_cspace_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_cspace_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_cspace_t new_value;

	do {
		new_value = cap_rights_cspace_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_cspace_t
cap_rights_cspace_atomic_intersection(_Atomic cap_rights_cspace_t *b1,
				      cap_rights_cspace_t	   b2,
				      memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_cspace_t not_b2 = cap_rights_cspace_inverse(b2);
	return cap_rights_cspace_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_cspace_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_cspace_t new_value;

	do {
		new_value = cap_rights_cspace_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_cspace_t
cap_rights_cspace_atomic_difference(_Atomic cap_rights_cspace_t *b1,
				    cap_rights_cspace_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_cspace_cast(ret_u);

#else
	cap_rights_cspace_t not_b2 = cap_rights_cspace_inverse(b2);
	return cap_rights_cspace_atomic_intersection(b1, not_b2, order);
#endif
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
						(uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_doorbell_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_doorbell_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_doorbell_t new_value;

	do {
		new_value = cap_rights_doorbell_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_doorbell_t
cap_rights_doorbell_atomic_intersection(_Atomic cap_rights_doorbell_t *b1,
					cap_rights_doorbell_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_doorbell_t not_b2 = cap_rights_doorbell_inverse(b2);
	return cap_rights_doorbell_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_doorbell_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_doorbell_t new_value;

	do {
		new_value = cap_rights_doorbell_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_doorbell_t
cap_rights_doorbell_atomic_difference(_Atomic cap_rights_doorbell_t *b1,
				      cap_rights_doorbell_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_doorbell_cast(ret_u);

#else
	cap_rights_doorbell_t not_b2 = cap_rights_doorbell_inverse(b2);
	return cap_rights_doorbell_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_generic_init(cap_rights_generic_t *bit_field)
{
	*bit_field = cap_rights_generic_default();
}

uint32_t
cap_rights_generic_raw(cap_rights_generic_t bit_field)
{
	return bit_field.bf[0];
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
					       (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_generic_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_generic_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_generic_t new_value;

	do {
		new_value = cap_rights_generic_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_generic_t
cap_rights_generic_atomic_intersection(_Atomic cap_rights_generic_t *b1,
				       cap_rights_generic_t	     b2,
				       memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_generic_t not_b2 = cap_rights_generic_inverse(b2);
	return cap_rights_generic_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_generic_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_generic_t new_value;

	do {
		new_value = cap_rights_generic_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_generic_t
cap_rights_generic_atomic_difference(_Atomic cap_rights_generic_t *b1,
				     cap_rights_generic_t	   b2,
				     memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_generic_cast(ret_u);

#else
	cap_rights_generic_t not_b2 = cap_rights_generic_inverse(b2);
	return cap_rights_generic_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_gicv3_its_init(cap_rights_gicv3_its_t *bit_field)
{
	*bit_field = cap_rights_gicv3_its_default();
}

uint32_t
cap_rights_gicv3_its_raw(cap_rights_gicv3_its_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_clean(cap_rights_gicv3_its_t bit_field)
{
	return (cap_rights_gicv3_its_t){ .bf = {
						 (bit_field.bf[0] & 0x80000001U),
					 } };
}

bool
cap_rights_gicv3_its_is_equal(cap_rights_gicv3_its_t b1,
			      cap_rights_gicv3_its_t b2)
{
	return ((b1.bf[0] & 0x80000001U) == (b2.bf[0] & 0x80000001U));
}

bool
cap_rights_gicv3_its_is_empty(cap_rights_gicv3_its_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000001U) == 0U);
}

bool
cap_rights_gicv3_its_is_clean(cap_rights_gicv3_its_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffeU) == 0x0U);
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_union(cap_rights_gicv3_its_t b1, cap_rights_gicv3_its_t b2)
{
	return (cap_rights_gicv3_its_t){ .bf = {
						 b1.bf[0] | b2.bf[0],
					 } };
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_intersection(cap_rights_gicv3_its_t b1,
				  cap_rights_gicv3_its_t b2)
{
	return (cap_rights_gicv3_its_t){ .bf = {
						 b1.bf[0] & b2.bf[0],
					 } };
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_inverse(cap_rights_gicv3_its_t b)
{
	return (cap_rights_gicv3_its_t){ .bf = {
						 (uint32_t)~b.bf[0],
					 } };
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_difference(cap_rights_gicv3_its_t b1,
				cap_rights_gicv3_its_t b2)
{
	cap_rights_gicv3_its_t not_b2 = cap_rights_gicv3_its_inverse(b2);
	return cap_rights_gicv3_its_intersection(b1, not_b2);
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_union(_Atomic cap_rights_gicv3_its_t *b1,
				  cap_rights_gicv3_its_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_gicv3_its_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_gicv3_its_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_gicv3_its_t new_value;

	do {
		new_value = cap_rights_gicv3_its_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_intersection(_Atomic cap_rights_gicv3_its_t *b1,
					 cap_rights_gicv3_its_t		 b2,
					 memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_gicv3_its_t not_b2 = cap_rights_gicv3_its_inverse(b2);
	return cap_rights_gicv3_its_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_gicv3_its_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_gicv3_its_t new_value;

	do {
		new_value = cap_rights_gicv3_its_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_gicv3_its_t
cap_rights_gicv3_its_atomic_difference(_Atomic cap_rights_gicv3_its_t *b1,
				       cap_rights_gicv3_its_t	       b2,
				       memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_gicv3_its_cast(ret_u);

#else
	cap_rights_gicv3_its_t not_b2 = cap_rights_gicv3_its_inverse(b2);
	return cap_rights_gicv3_its_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_gicv3_its_set_object_activate(cap_rights_gicv3_its_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_gicv3_its_get_object_activate(const cap_rights_gicv3_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_gicv3_its_copy_object_activate(
	cap_rights_gicv3_its_t	     *bit_field_dst,
	const cap_rights_gicv3_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_gicv3_its_set_bind_device(cap_rights_gicv3_its_t *bit_field,
				     bool		     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_gicv3_its_get_bind_device(const cap_rights_gicv3_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_gicv3_its_copy_bind_device(
	cap_rights_gicv3_its_t	     *bit_field_dst,
	const cap_rights_gicv3_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
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
					     (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_hwirq_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_hwirq_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_hwirq_t new_value;

	do {
		new_value = cap_rights_hwirq_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_hwirq_t
cap_rights_hwirq_atomic_intersection(_Atomic cap_rights_hwirq_t *b1,
				     cap_rights_hwirq_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_hwirq_t not_b2 = cap_rights_hwirq_inverse(b2);
	return cap_rights_hwirq_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_hwirq_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_hwirq_t new_value;

	do {
		new_value = cap_rights_hwirq_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_hwirq_t
cap_rights_hwirq_atomic_difference(_Atomic cap_rights_hwirq_t *b1,
				   cap_rights_hwirq_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_hwirq_cast(ret_u);

#else
	cap_rights_hwirq_t not_b2 = cap_rights_hwirq_inverse(b2);
	return cap_rights_hwirq_atomic_intersection(b1, not_b2, order);
#endif
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

cap_rights_memextent_t
cap_rights_memextent_clean(cap_rights_memextent_t bit_field)
{
	return (cap_rights_memextent_t){ .bf = {
						 (bit_field.bf[0] & 0x800000ffU),
					 } };
}

bool
cap_rights_memextent_is_equal(cap_rights_memextent_t b1,
			      cap_rights_memextent_t b2)
{
	return ((b1.bf[0] & 0x800000ffU) == (b2.bf[0] & 0x800000ffU));
}

bool
cap_rights_memextent_is_empty(cap_rights_memextent_t bit_field)
{
	return ((bit_field.bf[0] & 0x800000ffU) == 0U);
}

bool
cap_rights_memextent_is_clean(cap_rights_memextent_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffff00U) == 0x0U);
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
						 (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_memextent_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_memextent_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_memextent_t new_value;

	do {
		new_value = cap_rights_memextent_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_memextent_t
cap_rights_memextent_atomic_intersection(_Atomic cap_rights_memextent_t *b1,
					 cap_rights_memextent_t		 b2,
					 memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_memextent_t not_b2 = cap_rights_memextent_inverse(b2);
	return cap_rights_memextent_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_memextent_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_memextent_t new_value;

	do {
		new_value = cap_rights_memextent_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_memextent_t
cap_rights_memextent_atomic_difference(_Atomic cap_rights_memextent_t *b1,
				       cap_rights_memextent_t	       b2,
				       memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_memextent_cast(ret_u);

#else
	cap_rights_memextent_t not_b2 = cap_rights_memextent_inverse(b2);
	return cap_rights_memextent_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_memextent_set_protected_host(cap_rights_memextent_t *bit_field,
					bool			val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffdfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 5U;
}

bool
cap_rights_memextent_get_protected_host(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_protected_host(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x20U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x20U;
}

void
cap_rights_memextent_set_protected_guest(cap_rights_memextent_t *bit_field,
					 bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffbfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 6U;
}

bool
cap_rights_memextent_get_protected_guest(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_protected_guest(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x40U;
}

void
cap_rights_memextent_set_map_private(cap_rights_memextent_t *bit_field,
				     bool		     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff7fU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 7U;
}

bool
cap_rights_memextent_get_map_private(const cap_rights_memextent_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_memextent_copy_map_private(
	cap_rights_memextent_t	     *bit_field_dst,
	const cap_rights_memextent_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80U;
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
						(uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_msgqueue_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_msgqueue_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_msgqueue_t new_value;

	do {
		new_value = cap_rights_msgqueue_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_intersection(_Atomic cap_rights_msgqueue_t *b1,
					cap_rights_msgqueue_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_msgqueue_t not_b2 = cap_rights_msgqueue_inverse(b2);
	return cap_rights_msgqueue_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_msgqueue_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_msgqueue_t new_value;

	do {
		new_value = cap_rights_msgqueue_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_msgqueue_t
cap_rights_msgqueue_atomic_difference(_Atomic cap_rights_msgqueue_t *b1,
				      cap_rights_msgqueue_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_msgqueue_cast(ret_u);

#else
	cap_rights_msgqueue_t not_b2 = cap_rights_msgqueue_inverse(b2);
	return cap_rights_msgqueue_atomic_intersection(b1, not_b2, order);
#endif
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

cap_rights_partition_t
cap_rights_partition_clean(cap_rights_partition_t bit_field)
{
	return (cap_rights_partition_t){ .bf = {
						 (bit_field.bf[0] & 0x80000007U),
					 } };
}

bool
cap_rights_partition_is_equal(cap_rights_partition_t b1,
			      cap_rights_partition_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_partition_is_empty(cap_rights_partition_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_partition_is_clean(cap_rights_partition_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
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
						 (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_partition_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_partition_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_partition_t new_value;

	do {
		new_value = cap_rights_partition_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_partition_t
cap_rights_partition_atomic_intersection(_Atomic cap_rights_partition_t *b1,
					 cap_rights_partition_t		 b2,
					 memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_partition_t not_b2 = cap_rights_partition_inverse(b2);
	return cap_rights_partition_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_partition_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_partition_t new_value;

	do {
		new_value = cap_rights_partition_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_partition_t
cap_rights_partition_atomic_difference(_Atomic cap_rights_partition_t *b1,
				       cap_rights_partition_t	       b2,
				       memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_partition_cast(ret_u);

#else
	cap_rights_partition_t not_b2 = cap_rights_partition_inverse(b2);
	return cap_rights_partition_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_partition_set_query(cap_rights_partition_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_partition_get_query(const cap_rights_partition_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_partition_copy_query(cap_rights_partition_t	     *bit_field_dst,
				const cap_rights_partition_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
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
cap_rights_pci_function_init(cap_rights_pci_function_t *bit_field)
{
	*bit_field = cap_rights_pci_function_default();
}

uint32_t
cap_rights_pci_function_raw(cap_rights_pci_function_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_pci_function_t
cap_rights_pci_function_clean(cap_rights_pci_function_t bit_field)
{
	return (cap_rights_pci_function_t){ .bf = {
						    (bit_field.bf[0] &
						     0x80000003U),
					    } };
}

bool
cap_rights_pci_function_is_equal(cap_rights_pci_function_t b1,
				 cap_rights_pci_function_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_pci_function_is_empty(cap_rights_pci_function_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_pci_function_is_clean(cap_rights_pci_function_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_pci_function_t
cap_rights_pci_function_union(cap_rights_pci_function_t b1,
			      cap_rights_pci_function_t b2)
{
	return (cap_rights_pci_function_t){ .bf = {
						    b1.bf[0] | b2.bf[0],
					    } };
}

cap_rights_pci_function_t
cap_rights_pci_function_intersection(cap_rights_pci_function_t b1,
				     cap_rights_pci_function_t b2)
{
	return (cap_rights_pci_function_t){ .bf = {
						    b1.bf[0] & b2.bf[0],
					    } };
}

cap_rights_pci_function_t
cap_rights_pci_function_inverse(cap_rights_pci_function_t b)
{
	return (cap_rights_pci_function_t){ .bf = {
						    (uint32_t)~b.bf[0],
					    } };
}

cap_rights_pci_function_t
cap_rights_pci_function_difference(cap_rights_pci_function_t b1,
				   cap_rights_pci_function_t b2)
{
	cap_rights_pci_function_t not_b2 = cap_rights_pci_function_inverse(b2);
	return cap_rights_pci_function_intersection(b1, not_b2);
}

cap_rights_pci_function_t
cap_rights_pci_function_atomic_union(_Atomic cap_rights_pci_function_t *b1,
				     cap_rights_pci_function_t		b2,
				     memory_order			order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_pci_function_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_pci_function_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_pci_function_t new_value;

	do {
		new_value = cap_rights_pci_function_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_pci_function_t
cap_rights_pci_function_atomic_intersection(
	_Atomic cap_rights_pci_function_t *b1, cap_rights_pci_function_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_pci_function_t not_b2 = cap_rights_pci_function_inverse(b2);
	return cap_rights_pci_function_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_pci_function_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_pci_function_t new_value;

	do {
		new_value = cap_rights_pci_function_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_pci_function_t
cap_rights_pci_function_atomic_difference(_Atomic cap_rights_pci_function_t *b1,
					  cap_rights_pci_function_t	     b2,
					  memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_pci_function_cast(ret_u);

#else
	cap_rights_pci_function_t not_b2 = cap_rights_pci_function_inverse(b2);
	return cap_rights_pci_function_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_pci_function_set_passthrough(cap_rights_pci_function_t *bit_field,
					bool			   val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_pci_function_get_passthrough(
	const cap_rights_pci_function_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_function_copy_passthrough(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_pci_function_set_attach(cap_rights_pci_function_t *bit_field,
				   bool			      val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_pci_function_get_attach(const cap_rights_pci_function_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_function_copy_attach(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_pci_function_set_object_activate(
	cap_rights_pci_function_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_pci_function_get_object_activate(
	const cap_rights_pci_function_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_function_copy_object_activate(
	cap_rights_pci_function_t	*bit_field_dst,
	const cap_rights_pci_function_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_pci_host_init(cap_rights_pci_host_t *bit_field)
{
	*bit_field = cap_rights_pci_host_default();
}

uint32_t
cap_rights_pci_host_raw(cap_rights_pci_host_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_pci_host_t
cap_rights_pci_host_clean(cap_rights_pci_host_t bit_field)
{
	return (cap_rights_pci_host_t){ .bf = {
						(bit_field.bf[0] & 0x80000003U),
					} };
}

bool
cap_rights_pci_host_is_equal(cap_rights_pci_host_t b1, cap_rights_pci_host_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_pci_host_is_empty(cap_rights_pci_host_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_pci_host_is_clean(cap_rights_pci_host_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_pci_host_t
cap_rights_pci_host_union(cap_rights_pci_host_t b1, cap_rights_pci_host_t b2)
{
	return (cap_rights_pci_host_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

cap_rights_pci_host_t
cap_rights_pci_host_intersection(cap_rights_pci_host_t b1,
				 cap_rights_pci_host_t b2)
{
	return (cap_rights_pci_host_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

cap_rights_pci_host_t
cap_rights_pci_host_inverse(cap_rights_pci_host_t b)
{
	return (cap_rights_pci_host_t){ .bf = {
						(uint32_t)~b.bf[0],
					} };
}

cap_rights_pci_host_t
cap_rights_pci_host_difference(cap_rights_pci_host_t b1,
			       cap_rights_pci_host_t b2)
{
	cap_rights_pci_host_t not_b2 = cap_rights_pci_host_inverse(b2);
	return cap_rights_pci_host_intersection(b1, not_b2);
}

cap_rights_pci_host_t
cap_rights_pci_host_atomic_union(_Atomic cap_rights_pci_host_t *b1,
				 cap_rights_pci_host_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_pci_host_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_pci_host_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_pci_host_t new_value;

	do {
		new_value = cap_rights_pci_host_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_pci_host_t
cap_rights_pci_host_atomic_intersection(_Atomic cap_rights_pci_host_t *b1,
					cap_rights_pci_host_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_pci_host_t not_b2 = cap_rights_pci_host_inverse(b2);
	return cap_rights_pci_host_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_pci_host_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_pci_host_t new_value;

	do {
		new_value = cap_rights_pci_host_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_pci_host_t
cap_rights_pci_host_atomic_difference(_Atomic cap_rights_pci_host_t *b1,
				      cap_rights_pci_host_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_pci_host_cast(ret_u);

#else
	cap_rights_pci_host_t not_b2 = cap_rights_pci_host_inverse(b2);
	return cap_rights_pci_host_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_pci_host_set_create_function(cap_rights_pci_host_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_pci_host_get_create_function(const cap_rights_pci_host_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_host_copy_create_function(
	cap_rights_pci_host_t	    *bit_field_dst,
	const cap_rights_pci_host_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_pci_host_set_set_lockdown(cap_rights_pci_host_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_pci_host_get_set_lockdown(const cap_rights_pci_host_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_host_copy_set_lockdown(cap_rights_pci_host_t *bit_field_dst,
				      const cap_rights_pci_host_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_pci_host_set_object_activate(cap_rights_pci_host_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_pci_host_get_object_activate(const cap_rights_pci_host_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_pci_host_copy_object_activate(
	cap_rights_pci_host_t	    *bit_field_dst,
	const cap_rights_pci_host_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_power_init(cap_rights_power_t *bit_field)
{
	*bit_field = cap_rights_power_default();
}

uint32_t
cap_rights_power_raw(cap_rights_power_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_power_t
cap_rights_power_clean(cap_rights_power_t bit_field)
{
	return (cap_rights_power_t){ .bf = {
					     (bit_field.bf[0] & 0x80000003U),
				     } };
}

bool
cap_rights_power_is_equal(cap_rights_power_t b1, cap_rights_power_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_power_is_empty(cap_rights_power_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_power_is_clean(cap_rights_power_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_power_t
cap_rights_power_union(cap_rights_power_t b1, cap_rights_power_t b2)
{
	return (cap_rights_power_t){ .bf = {
					     b1.bf[0] | b2.bf[0],
				     } };
}

cap_rights_power_t
cap_rights_power_intersection(cap_rights_power_t b1, cap_rights_power_t b2)
{
	return (cap_rights_power_t){ .bf = {
					     b1.bf[0] & b2.bf[0],
				     } };
}

cap_rights_power_t
cap_rights_power_inverse(cap_rights_power_t b)
{
	return (cap_rights_power_t){ .bf = {
					     (uint32_t)~b.bf[0],
				     } };
}

cap_rights_power_t
cap_rights_power_difference(cap_rights_power_t b1, cap_rights_power_t b2)
{
	cap_rights_power_t not_b2 = cap_rights_power_inverse(b2);
	return cap_rights_power_intersection(b1, not_b2);
}

cap_rights_power_t
cap_rights_power_atomic_union(_Atomic cap_rights_power_t *b1,
			      cap_rights_power_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_power_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_power_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_power_t new_value;

	do {
		new_value = cap_rights_power_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_power_t
cap_rights_power_atomic_intersection(_Atomic cap_rights_power_t *b1,
				     cap_rights_power_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_power_t not_b2 = cap_rights_power_inverse(b2);
	return cap_rights_power_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_power_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_power_t new_value;

	do {
		new_value = cap_rights_power_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_power_t
cap_rights_power_atomic_difference(_Atomic cap_rights_power_t *b1,
				   cap_rights_power_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_power_cast(ret_u);

#else
	cap_rights_power_t not_b2 = cap_rights_power_inverse(b2);
	return cap_rights_power_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_power_set_system_suspend(cap_rights_power_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_power_get_system_suspend(const cap_rights_power_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_power_copy_system_suspend(cap_rights_power_t	      *bit_field_dst,
				     const cap_rights_power_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_power_set_cpu_suspend(cap_rights_power_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_power_get_cpu_suspend(const cap_rights_power_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_power_copy_cpu_suspend(cap_rights_power_t	   *bit_field_dst,
				  const cap_rights_power_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_power_set_object_activate(cap_rights_power_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_power_get_object_activate(const cap_rights_power_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_power_copy_object_activate(cap_rights_power_t       *bit_field_dst,
				      const cap_rights_power_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_smmuv3_init(cap_rights_smmuv3_t *bit_field)
{
	*bit_field = cap_rights_smmuv3_default();
}

uint32_t
cap_rights_smmuv3_raw(cap_rights_smmuv3_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_smmuv3_t
cap_rights_smmuv3_clean(cap_rights_smmuv3_t bit_field)
{
	return (cap_rights_smmuv3_t){ .bf = {
					      (bit_field.bf[0] & 0x80000003U),
				      } };
}

bool
cap_rights_smmuv3_is_equal(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_smmuv3_is_empty(cap_rights_smmuv3_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_smmuv3_is_clean(cap_rights_smmuv3_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_smmuv3_t
cap_rights_smmuv3_union(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2)
{
	return (cap_rights_smmuv3_t){ .bf = {
					      b1.bf[0] | b2.bf[0],
				      } };
}

cap_rights_smmuv3_t
cap_rights_smmuv3_intersection(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2)
{
	return (cap_rights_smmuv3_t){ .bf = {
					      b1.bf[0] & b2.bf[0],
				      } };
}

cap_rights_smmuv3_t
cap_rights_smmuv3_inverse(cap_rights_smmuv3_t b)
{
	return (cap_rights_smmuv3_t){ .bf = {
					      (uint32_t)~b.bf[0],
				      } };
}

cap_rights_smmuv3_t
cap_rights_smmuv3_difference(cap_rights_smmuv3_t b1, cap_rights_smmuv3_t b2)
{
	cap_rights_smmuv3_t not_b2 = cap_rights_smmuv3_inverse(b2);
	return cap_rights_smmuv3_intersection(b1, not_b2);
}

cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_union(_Atomic cap_rights_smmuv3_t *b1,
			       cap_rights_smmuv3_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_smmuv3_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_smmuv3_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_smmuv3_t new_value;

	do {
		new_value = cap_rights_smmuv3_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_intersection(_Atomic cap_rights_smmuv3_t *b1,
				      cap_rights_smmuv3_t	   b2,
				      memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_smmuv3_t not_b2 = cap_rights_smmuv3_inverse(b2);
	return cap_rights_smmuv3_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_smmuv3_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_smmuv3_t new_value;

	do {
		new_value = cap_rights_smmuv3_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_smmuv3_t
cap_rights_smmuv3_atomic_difference(_Atomic cap_rights_smmuv3_t *b1,
				    cap_rights_smmuv3_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_smmuv3_cast(ret_u);

#else
	cap_rights_smmuv3_t not_b2 = cap_rights_smmuv3_inverse(b2);
	return cap_rights_smmuv3_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_smmuv3_set_object_activate(cap_rights_smmuv3_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_smmuv3_get_object_activate(const cap_rights_smmuv3_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_smmuv3_copy_object_activate(cap_rights_smmuv3_t	 *bit_field_dst,
				       const cap_rights_smmuv3_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_smmuv3_set_configure(cap_rights_smmuv3_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_smmuv3_get_configure(const cap_rights_smmuv3_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_smmuv3_copy_configure(cap_rights_smmuv3_t	   *bit_field_dst,
				 const cap_rights_smmuv3_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_smmuv3_set_manage_streams(cap_rights_smmuv3_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_smmuv3_get_manage_streams(const cap_rights_smmuv3_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_smmuv3_copy_manage_streams(cap_rights_smmuv3_t	*bit_field_dst,
				      const cap_rights_smmuv3_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
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

cap_rights_thread_t
cap_rights_thread_clean(cap_rights_thread_t bit_field)
{
	return (cap_rights_thread_t){ .bf = {
					      (bit_field.bf[0] & 0x800007ffU),
				      } };
}

bool
cap_rights_thread_is_equal(cap_rights_thread_t b1, cap_rights_thread_t b2)
{
	return ((b1.bf[0] & 0x800007ffU) == (b2.bf[0] & 0x800007ffU));
}

bool
cap_rights_thread_is_empty(cap_rights_thread_t bit_field)
{
	return ((bit_field.bf[0] & 0x800007ffU) == 0U);
}

bool
cap_rights_thread_is_clean(cap_rights_thread_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffff800U) == 0x0U);
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
					      (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_thread_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_thread_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_thread_t new_value;

	do {
		new_value = cap_rights_thread_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_thread_t
cap_rights_thread_atomic_intersection(_Atomic cap_rights_thread_t *b1,
				      cap_rights_thread_t	   b2,
				      memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_thread_t not_b2 = cap_rights_thread_inverse(b2);
	return cap_rights_thread_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_thread_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_thread_t new_value;

	do {
		new_value = cap_rights_thread_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_thread_t
cap_rights_thread_atomic_difference(_Atomic cap_rights_thread_t *b1,
				    cap_rights_thread_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_thread_cast(ret_u);

#else
	cap_rights_thread_t not_b2 = cap_rights_thread_inverse(b2);
	return cap_rights_thread_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_thread_set_bind_local_virq(cap_rights_thread_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffbffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 10U;
}

bool
cap_rights_thread_get_bind_local_virq(const cap_rights_thread_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 10U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_thread_copy_bind_local_virq(cap_rights_thread_t	 *bit_field_dst,
				       const cap_rights_thread_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x400U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x400U;
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
cap_rights_vgic_its_init(cap_rights_vgic_its_t *bit_field)
{
	*bit_field = cap_rights_vgic_its_default();
}

uint32_t
cap_rights_vgic_its_raw(cap_rights_vgic_its_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_vgic_its_t
cap_rights_vgic_its_clean(cap_rights_vgic_its_t bit_field)
{
	return (cap_rights_vgic_its_t){ .bf = {
						(bit_field.bf[0] & 0x8000000fU),
					} };
}

bool
cap_rights_vgic_its_is_equal(cap_rights_vgic_its_t b1, cap_rights_vgic_its_t b2)
{
	return ((b1.bf[0] & 0x8000000fU) == (b2.bf[0] & 0x8000000fU));
}

bool
cap_rights_vgic_its_is_empty(cap_rights_vgic_its_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000fU) == 0U);
}

bool
cap_rights_vgic_its_is_clean(cap_rights_vgic_its_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff0U) == 0x0U);
}

cap_rights_vgic_its_t
cap_rights_vgic_its_union(cap_rights_vgic_its_t b1, cap_rights_vgic_its_t b2)
{
	return (cap_rights_vgic_its_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

cap_rights_vgic_its_t
cap_rights_vgic_its_intersection(cap_rights_vgic_its_t b1,
				 cap_rights_vgic_its_t b2)
{
	return (cap_rights_vgic_its_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

cap_rights_vgic_its_t
cap_rights_vgic_its_inverse(cap_rights_vgic_its_t b)
{
	return (cap_rights_vgic_its_t){ .bf = {
						(uint32_t)~b.bf[0],
					} };
}

cap_rights_vgic_its_t
cap_rights_vgic_its_difference(cap_rights_vgic_its_t b1,
			       cap_rights_vgic_its_t b2)
{
	cap_rights_vgic_its_t not_b2 = cap_rights_vgic_its_inverse(b2);
	return cap_rights_vgic_its_intersection(b1, not_b2);
}

cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_union(_Atomic cap_rights_vgic_its_t *b1,
				 cap_rights_vgic_its_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vgic_its_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vgic_its_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vgic_its_t new_value;

	do {
		new_value = cap_rights_vgic_its_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_intersection(_Atomic cap_rights_vgic_its_t *b1,
					cap_rights_vgic_its_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vgic_its_t not_b2 = cap_rights_vgic_its_inverse(b2);
	return cap_rights_vgic_its_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vgic_its_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vgic_its_t new_value;

	do {
		new_value = cap_rights_vgic_its_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vgic_its_t
cap_rights_vgic_its_atomic_difference(_Atomic cap_rights_vgic_its_t *b1,
				      cap_rights_vgic_its_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vgic_its_cast(ret_u);

#else
	cap_rights_vgic_its_t not_b2 = cap_rights_vgic_its_inverse(b2);
	return cap_rights_vgic_its_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_vgic_its_set_object_activate(cap_rights_vgic_its_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vgic_its_get_object_activate(const cap_rights_vgic_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vgic_its_copy_object_activate(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_vgic_its_set_bind_vic(cap_rights_vgic_its_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vgic_its_get_bind_vic(const cap_rights_vgic_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vgic_its_copy_bind_vic(cap_rights_vgic_its_t	      *bit_field_dst,
				  const cap_rights_vgic_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vgic_its_set_attach_addrspace(cap_rights_vgic_its_t *bit_field,
					 bool			val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vgic_its_get_attach_addrspace(const cap_rights_vgic_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vgic_its_copy_attach_addrspace(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vgic_its_set_bind_devices(cap_rights_vgic_its_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_vgic_its_get_bind_devices(const cap_rights_vgic_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vgic_its_copy_bind_devices(cap_rights_vgic_its_t *bit_field_dst,
				      const cap_rights_vgic_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_vgic_its_set_unbind_devices(cap_rights_vgic_its_t *bit_field,
				       bool		      val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_vgic_its_get_unbind_devices(const cap_rights_vgic_its_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vgic_its_copy_unbind_devices(
	cap_rights_vgic_its_t	    *bit_field_dst,
	const cap_rights_vgic_its_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
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
					   (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vic_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vic_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vic_t new_value;

	do {
		new_value = cap_rights_vic_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vic_t
cap_rights_vic_atomic_intersection(_Atomic cap_rights_vic_t *b1,
				   cap_rights_vic_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vic_t not_b2 = cap_rights_vic_inverse(b2);
	return cap_rights_vic_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vic_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vic_t new_value;

	do {
		new_value = cap_rights_vic_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vic_t
cap_rights_vic_atomic_difference(_Atomic cap_rights_vic_t *b1,
				 cap_rights_vic_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vic_cast(ret_u);

#else
	cap_rights_vic_t not_b2 = cap_rights_vic_inverse(b2);
	return cap_rights_vic_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_virtio_backend_init(cap_rights_virtio_backend_t *bit_field)
{
	*bit_field = cap_rights_virtio_backend_default();
}

uint32_t
cap_rights_virtio_backend_raw(cap_rights_virtio_backend_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_clean(cap_rights_virtio_backend_t bit_field)
{
	return (cap_rights_virtio_backend_t){ .bf = {
						      (bit_field.bf[0] &
						       0x8000001fU),
					      } };
}

bool
cap_rights_virtio_backend_is_equal(cap_rights_virtio_backend_t b1,
				   cap_rights_virtio_backend_t b2)
{
	return ((b1.bf[0] & 0x8000001fU) == (b2.bf[0] & 0x8000001fU));
}

bool
cap_rights_virtio_backend_is_empty(cap_rights_virtio_backend_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000001fU) == 0U);
}

bool
cap_rights_virtio_backend_is_clean(cap_rights_virtio_backend_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffe0U) == 0x0U);
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_union(cap_rights_virtio_backend_t b1,
				cap_rights_virtio_backend_t b2)
{
	return (cap_rights_virtio_backend_t){ .bf = {
						      b1.bf[0] | b2.bf[0],
					      } };
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_intersection(cap_rights_virtio_backend_t b1,
				       cap_rights_virtio_backend_t b2)
{
	return (cap_rights_virtio_backend_t){ .bf = {
						      b1.bf[0] & b2.bf[0],
					      } };
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_inverse(cap_rights_virtio_backend_t b)
{
	return (cap_rights_virtio_backend_t){ .bf = {
						      (uint32_t)~b.bf[0],
					      } };
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_difference(cap_rights_virtio_backend_t b1,
				     cap_rights_virtio_backend_t b2)
{
	cap_rights_virtio_backend_t not_b2 =
		cap_rights_virtio_backend_inverse(b2);
	return cap_rights_virtio_backend_intersection(b1, not_b2);
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_union(_Atomic cap_rights_virtio_backend_t *b1,
				       cap_rights_virtio_backend_t	    b2,
				       memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_virtio_backend_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_virtio_backend_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_virtio_backend_t new_value;

	do {
		new_value = cap_rights_virtio_backend_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_intersection(
	_Atomic cap_rights_virtio_backend_t *b1, cap_rights_virtio_backend_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_virtio_backend_t not_b2 =
		cap_rights_virtio_backend_inverse(b2);
	return cap_rights_virtio_backend_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_virtio_backend_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_virtio_backend_t new_value;

	do {
		new_value =
			cap_rights_virtio_backend_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_virtio_backend_t
cap_rights_virtio_backend_atomic_difference(
	_Atomic cap_rights_virtio_backend_t *b1, cap_rights_virtio_backend_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_virtio_backend_cast(ret_u);

#else
	cap_rights_virtio_backend_t not_b2 =
		cap_rights_virtio_backend_inverse(b2);
	return cap_rights_virtio_backend_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_virtio_backend_set_bind_virq(cap_rights_virtio_backend_t *bit_field,
					bool			     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_virtio_backend_get_bind_virq(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_bind_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_virtio_backend_set_assert_virq(
	cap_rights_virtio_backend_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_virtio_backend_get_assert_virq(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_assert_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_virtio_backend_set_config(cap_rights_virtio_backend_t *bit_field,
				     bool			  val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_virtio_backend_get_config(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_config(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_virtio_backend_set_bind_mmio_frontend_virq(
	cap_rights_virtio_backend_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_virtio_backend_get_bind_mmio_frontend_virq(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_bind_mmio_frontend_virq(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_virtio_backend_set_bind_vpci(cap_rights_virtio_backend_t *bit_field,
					bool			     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_virtio_backend_get_bind_vpci(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_bind_vpci(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_virtio_backend_set_object_activate(
	cap_rights_virtio_backend_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_virtio_backend_get_object_activate(
	const cap_rights_virtio_backend_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_backend_copy_object_activate(
	cap_rights_virtio_backend_t	  *bit_field_dst,
	const cap_rights_virtio_backend_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_virtio_iommu_init(cap_rights_virtio_iommu_t *bit_field)
{
	*bit_field = cap_rights_virtio_iommu_default();
}

uint32_t
cap_rights_virtio_iommu_raw(cap_rights_virtio_iommu_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_clean(cap_rights_virtio_iommu_t bit_field)
{
	return (cap_rights_virtio_iommu_t){ .bf = {
						    (bit_field.bf[0] &
						     0x80000003U),
					    } };
}

bool
cap_rights_virtio_iommu_is_equal(cap_rights_virtio_iommu_t b1,
				 cap_rights_virtio_iommu_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_virtio_iommu_is_empty(cap_rights_virtio_iommu_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_virtio_iommu_is_clean(cap_rights_virtio_iommu_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_union(cap_rights_virtio_iommu_t b1,
			      cap_rights_virtio_iommu_t b2)
{
	return (cap_rights_virtio_iommu_t){ .bf = {
						    b1.bf[0] | b2.bf[0],
					    } };
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_intersection(cap_rights_virtio_iommu_t b1,
				     cap_rights_virtio_iommu_t b2)
{
	return (cap_rights_virtio_iommu_t){ .bf = {
						    b1.bf[0] & b2.bf[0],
					    } };
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_inverse(cap_rights_virtio_iommu_t b)
{
	return (cap_rights_virtio_iommu_t){ .bf = {
						    (uint32_t)~b.bf[0],
					    } };
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_difference(cap_rights_virtio_iommu_t b1,
				   cap_rights_virtio_iommu_t b2)
{
	cap_rights_virtio_iommu_t not_b2 = cap_rights_virtio_iommu_inverse(b2);
	return cap_rights_virtio_iommu_intersection(b1, not_b2);
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_union(_Atomic cap_rights_virtio_iommu_t *b1,
				     cap_rights_virtio_iommu_t		b2,
				     memory_order			order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_virtio_iommu_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_virtio_iommu_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_virtio_iommu_t new_value;

	do {
		new_value = cap_rights_virtio_iommu_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_intersection(
	_Atomic cap_rights_virtio_iommu_t *b1, cap_rights_virtio_iommu_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_virtio_iommu_t not_b2 = cap_rights_virtio_iommu_inverse(b2);
	return cap_rights_virtio_iommu_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_virtio_iommu_t old_value =
		atomic_load_explicit(b1, load_order);
	cap_rights_virtio_iommu_t new_value;

	do {
		new_value = cap_rights_virtio_iommu_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_virtio_iommu_t
cap_rights_virtio_iommu_atomic_difference(_Atomic cap_rights_virtio_iommu_t *b1,
					  cap_rights_virtio_iommu_t	     b2,
					  memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_virtio_iommu_cast(ret_u);

#else
	cap_rights_virtio_iommu_t not_b2 = cap_rights_virtio_iommu_inverse(b2);
	return cap_rights_virtio_iommu_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_virtio_iommu_set_bind_vpci(cap_rights_virtio_iommu_t *bit_field,
				      bool			 val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_virtio_iommu_get_bind_vpci(const cap_rights_virtio_iommu_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_iommu_copy_bind_vpci(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_virtio_iommu_set_manage_streams(cap_rights_virtio_iommu_t *bit_field,
					   bool			      val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_virtio_iommu_get_manage_streams(
	const cap_rights_virtio_iommu_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_iommu_copy_manage_streams(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_virtio_iommu_set_object_activate(
	cap_rights_virtio_iommu_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_virtio_iommu_get_object_activate(
	const cap_rights_virtio_iommu_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_virtio_iommu_copy_object_activate(
	cap_rights_virtio_iommu_t	*bit_field_dst,
	const cap_rights_virtio_iommu_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_vpci_init(cap_rights_vpci_t *bit_field)
{
	*bit_field = cap_rights_vpci_default();
}

uint32_t
cap_rights_vpci_raw(cap_rights_vpci_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_vpci_t
cap_rights_vpci_clean(cap_rights_vpci_t bit_field)
{
	return (cap_rights_vpci_t){ .bf = {
					    (bit_field.bf[0] & 0x80000003U),
				    } };
}

bool
cap_rights_vpci_is_equal(cap_rights_vpci_t b1, cap_rights_vpci_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_vpci_is_empty(cap_rights_vpci_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_vpci_is_clean(cap_rights_vpci_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_vpci_t
cap_rights_vpci_union(cap_rights_vpci_t b1, cap_rights_vpci_t b2)
{
	return (cap_rights_vpci_t){ .bf = {
					    b1.bf[0] | b2.bf[0],
				    } };
}

cap_rights_vpci_t
cap_rights_vpci_intersection(cap_rights_vpci_t b1, cap_rights_vpci_t b2)
{
	return (cap_rights_vpci_t){ .bf = {
					    b1.bf[0] & b2.bf[0],
				    } };
}

cap_rights_vpci_t
cap_rights_vpci_inverse(cap_rights_vpci_t b)
{
	return (cap_rights_vpci_t){ .bf = {
					    (uint32_t)~b.bf[0],
				    } };
}

cap_rights_vpci_t
cap_rights_vpci_difference(cap_rights_vpci_t b1, cap_rights_vpci_t b2)
{
	cap_rights_vpci_t not_b2 = cap_rights_vpci_inverse(b2);
	return cap_rights_vpci_intersection(b1, not_b2);
}

cap_rights_vpci_t
cap_rights_vpci_atomic_union(_Atomic cap_rights_vpci_t *b1,
			     cap_rights_vpci_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vpci_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vpci_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vpci_t new_value;

	do {
		new_value = cap_rights_vpci_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vpci_t
cap_rights_vpci_atomic_intersection(_Atomic cap_rights_vpci_t *b1,
				    cap_rights_vpci_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vpci_t not_b2 = cap_rights_vpci_inverse(b2);
	return cap_rights_vpci_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vpci_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vpci_t new_value;

	do {
		new_value = cap_rights_vpci_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vpci_t
cap_rights_vpci_atomic_difference(_Atomic cap_rights_vpci_t *b1,
				  cap_rights_vpci_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vpci_cast(ret_u);

#else
	cap_rights_vpci_t not_b2 = cap_rights_vpci_inverse(b2);
	return cap_rights_vpci_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_vpci_set_attach(cap_rights_vpci_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vpci_get_attach(const cap_rights_vpci_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpci_copy_attach(cap_rights_vpci_t	    *bit_field_dst,
			    const cap_rights_vpci_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vpci_set_bind(cap_rights_vpci_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vpci_get_bind(const cap_rights_vpci_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpci_copy_bind(cap_rights_vpci_t	  *bit_field_dst,
			  const cap_rights_vpci_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vpci_set_object_activate(cap_rights_vpci_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vpci_get_object_activate(const cap_rights_vpci_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpci_copy_object_activate(cap_rights_vpci_t	     *bit_field_dst,
				     const cap_rights_vpci_t *bit_field_src)
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

cap_rights_vpm_group_t
cap_rights_vpm_group_clean(cap_rights_vpm_group_t bit_field)
{
	return (cap_rights_vpm_group_t){ .bf = {
						 (bit_field.bf[0] & 0x8000003fU),
					 } };
}

bool
cap_rights_vpm_group_is_equal(cap_rights_vpm_group_t b1,
			      cap_rights_vpm_group_t b2)
{
	return ((b1.bf[0] & 0x8000003fU) == (b2.bf[0] & 0x8000003fU));
}

bool
cap_rights_vpm_group_is_empty(cap_rights_vpm_group_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000003fU) == 0U);
}

bool
cap_rights_vpm_group_is_clean(cap_rights_vpm_group_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffc0U) == 0x0U);
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
						 (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vpm_group_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vpm_group_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vpm_group_t new_value;

	do {
		new_value = cap_rights_vpm_group_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_intersection(_Atomic cap_rights_vpm_group_t *b1,
					 cap_rights_vpm_group_t		 b2,
					 memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vpm_group_t not_b2 = cap_rights_vpm_group_inverse(b2);
	return cap_rights_vpm_group_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vpm_group_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vpm_group_t new_value;

	do {
		new_value = cap_rights_vpm_group_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vpm_group_t
cap_rights_vpm_group_atomic_difference(_Atomic cap_rights_vpm_group_t *b1,
				       cap_rights_vpm_group_t	       b2,
				       memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vpm_group_cast(ret_u);

#else
	cap_rights_vpm_group_t not_b2 = cap_rights_vpm_group_inverse(b2);
	return cap_rights_vpm_group_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_vpm_group_set_wakeup(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 3U;
}

bool
cap_rights_vpm_group_get_wakeup(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_wakeup(cap_rights_vpm_group_t	      *bit_field_dst,
				 const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x8U;
}

void
cap_rights_vpm_group_set_bind_power(cap_rights_vpm_group_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 4U;
}

bool
cap_rights_vpm_group_get_bind_power(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_bind_power(cap_rights_vpm_group_t *bit_field_dst,
				     const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x10U;
}

void
cap_rights_vpm_group_set_set_threshold(cap_rights_vpm_group_t *bit_field,
				       bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffffdfU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 5U;
}

bool
cap_rights_vpm_group_get_set_threshold(const cap_rights_vpm_group_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 5U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vpm_group_copy_set_threshold(
	cap_rights_vpm_group_t	     *bit_field_dst,
	const cap_rights_vpm_group_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x20U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x20U;
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
					    (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vrtc_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vrtc_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vrtc_t new_value;

	do {
		new_value = cap_rights_vrtc_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vrtc_t
cap_rights_vrtc_atomic_intersection(_Atomic cap_rights_vrtc_t *b1,
				    cap_rights_vrtc_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vrtc_t not_b2 = cap_rights_vrtc_inverse(b2);
	return cap_rights_vrtc_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vrtc_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vrtc_t new_value;

	do {
		new_value = cap_rights_vrtc_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vrtc_t
cap_rights_vrtc_atomic_difference(_Atomic cap_rights_vrtc_t *b1,
				  cap_rights_vrtc_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vrtc_cast(ret_u);

#else
	cap_rights_vrtc_t not_b2 = cap_rights_vrtc_inverse(b2);
	return cap_rights_vrtc_atomic_intersection(b1, not_b2, order);
#endif
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
cap_rights_vsmmuv2_init(cap_rights_vsmmuv2_t *bit_field)
{
	*bit_field = cap_rights_vsmmuv2_default();
}

uint32_t
cap_rights_vsmmuv2_raw(cap_rights_vsmmuv2_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_clean(cap_rights_vsmmuv2_t bit_field)
{
	return (cap_rights_vsmmuv2_t){ .bf = {
					       (bit_field.bf[0] & 0x80000003U),
				       } };
}

bool
cap_rights_vsmmuv2_is_equal(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2)
{
	return ((b1.bf[0] & 0x80000003U) == (b2.bf[0] & 0x80000003U));
}

bool
cap_rights_vsmmuv2_is_empty(cap_rights_vsmmuv2_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000003U) == 0U);
}

bool
cap_rights_vsmmuv2_is_clean(cap_rights_vsmmuv2_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffcU) == 0x0U);
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_union(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2)
{
	return (cap_rights_vsmmuv2_t){ .bf = {
					       b1.bf[0] | b2.bf[0],
				       } };
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_intersection(cap_rights_vsmmuv2_t b1,
				cap_rights_vsmmuv2_t b2)
{
	return (cap_rights_vsmmuv2_t){ .bf = {
					       b1.bf[0] & b2.bf[0],
				       } };
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_inverse(cap_rights_vsmmuv2_t b)
{
	return (cap_rights_vsmmuv2_t){ .bf = {
					       (uint32_t)~b.bf[0],
				       } };
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_difference(cap_rights_vsmmuv2_t b1, cap_rights_vsmmuv2_t b2)
{
	cap_rights_vsmmuv2_t not_b2 = cap_rights_vsmmuv2_inverse(b2);
	return cap_rights_vsmmuv2_intersection(b1, not_b2);
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_union(_Atomic cap_rights_vsmmuv2_t *b1,
				cap_rights_vsmmuv2_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vsmmuv2_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vsmmuv2_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vsmmuv2_t new_value;

	do {
		new_value = cap_rights_vsmmuv2_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_intersection(_Atomic cap_rights_vsmmuv2_t *b1,
				       cap_rights_vsmmuv2_t	     b2,
				       memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_vsmmuv2_t not_b2 = cap_rights_vsmmuv2_inverse(b2);
	return cap_rights_vsmmuv2_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_vsmmuv2_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_vsmmuv2_t new_value;

	do {
		new_value = cap_rights_vsmmuv2_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_vsmmuv2_t
cap_rights_vsmmuv2_atomic_difference(_Atomic cap_rights_vsmmuv2_t *b1,
				     cap_rights_vsmmuv2_t	   b2,
				     memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_vsmmuv2_cast(ret_u);

#else
	cap_rights_vsmmuv2_t not_b2 = cap_rights_vsmmuv2_inverse(b2);
	return cap_rights_vsmmuv2_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_vsmmuv2_set_manage_streams(cap_rights_vsmmuv2_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_vsmmuv2_get_manage_streams(const cap_rights_vsmmuv2_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vsmmuv2_copy_manage_streams(cap_rights_vsmmuv2_t *bit_field_dst,
				       const cap_rights_vsmmuv2_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_vsmmuv2_set_attach_addrspace(cap_rights_vsmmuv2_t *bit_field,
					bool		      val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_vsmmuv2_get_attach_addrspace(const cap_rights_vsmmuv2_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vsmmuv2_copy_attach_addrspace(
	cap_rights_vsmmuv2_t	   *bit_field_dst,
	const cap_rights_vsmmuv2_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_vsmmuv2_set_object_activate(cap_rights_vsmmuv2_t *bit_field,
				       bool		     val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_vsmmuv2_get_object_activate(const cap_rights_vsmmuv2_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_vsmmuv2_copy_object_activate(
	cap_rights_vsmmuv2_t	   *bit_field_dst,
	const cap_rights_vsmmuv2_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
}

void
cap_rights_watchdog_init(cap_rights_watchdog_t *bit_field)
{
	*bit_field = cap_rights_watchdog_default();
}

uint32_t
cap_rights_watchdog_raw(cap_rights_watchdog_t bit_field)
{
	return bit_field.bf[0];
}

cap_rights_watchdog_t
cap_rights_watchdog_clean(cap_rights_watchdog_t bit_field)
{
	return (cap_rights_watchdog_t){ .bf = {
						(bit_field.bf[0] & 0x80000007U),
					} };
}

bool
cap_rights_watchdog_is_equal(cap_rights_watchdog_t b1, cap_rights_watchdog_t b2)
{
	return ((b1.bf[0] & 0x80000007U) == (b2.bf[0] & 0x80000007U));
}

bool
cap_rights_watchdog_is_empty(cap_rights_watchdog_t bit_field)
{
	return ((bit_field.bf[0] & 0x80000007U) == 0U);
}

bool
cap_rights_watchdog_is_clean(cap_rights_watchdog_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffff8U) == 0x0U);
}

cap_rights_watchdog_t
cap_rights_watchdog_union(cap_rights_watchdog_t b1, cap_rights_watchdog_t b2)
{
	return (cap_rights_watchdog_t){ .bf = {
						b1.bf[0] | b2.bf[0],
					} };
}

cap_rights_watchdog_t
cap_rights_watchdog_intersection(cap_rights_watchdog_t b1,
				 cap_rights_watchdog_t b2)
{
	return (cap_rights_watchdog_t){ .bf = {
						b1.bf[0] & b2.bf[0],
					} };
}

cap_rights_watchdog_t
cap_rights_watchdog_inverse(cap_rights_watchdog_t b)
{
	return (cap_rights_watchdog_t){ .bf = {
						(uint32_t)~b.bf[0],
					} };
}

cap_rights_watchdog_t
cap_rights_watchdog_difference(cap_rights_watchdog_t b1,
			       cap_rights_watchdog_t b2)
{
	cap_rights_watchdog_t not_b2 = cap_rights_watchdog_inverse(b2);
	return cap_rights_watchdog_intersection(b1, not_b2);
}

cap_rights_watchdog_t
cap_rights_watchdog_atomic_union(_Atomic cap_rights_watchdog_t *b1,
				 cap_rights_watchdog_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_watchdog_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_watchdog_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_watchdog_t new_value;

	do {
		new_value = cap_rights_watchdog_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_watchdog_t
cap_rights_watchdog_atomic_intersection(_Atomic cap_rights_watchdog_t *b1,
					cap_rights_watchdog_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	cap_rights_watchdog_t not_b2 = cap_rights_watchdog_inverse(b2);
	return cap_rights_watchdog_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	cap_rights_watchdog_t old_value = atomic_load_explicit(b1, load_order);
	cap_rights_watchdog_t new_value;

	do {
		new_value = cap_rights_watchdog_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

cap_rights_watchdog_t
cap_rights_watchdog_atomic_difference(_Atomic cap_rights_watchdog_t *b1,
				      cap_rights_watchdog_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return cap_rights_watchdog_cast(ret_u);

#else
	cap_rights_watchdog_t not_b2 = cap_rights_watchdog_inverse(b2);
	return cap_rights_watchdog_atomic_intersection(b1, not_b2, order);
#endif
}

void
cap_rights_watchdog_set_attach_vcpu(cap_rights_watchdog_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 0U;
}

bool
cap_rights_watchdog_get_attach_vcpu(const cap_rights_watchdog_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_watchdog_copy_attach_vcpu(cap_rights_watchdog_t	 *bit_field_dst,
				     const cap_rights_watchdog_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x1U;
}

void
cap_rights_watchdog_set_bind_virq(cap_rights_watchdog_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 1U;
}

bool
cap_rights_watchdog_get_bind_virq(const cap_rights_watchdog_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_watchdog_copy_bind_virq(cap_rights_watchdog_t       *bit_field_dst,
				   const cap_rights_watchdog_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x2U;
}

void
cap_rights_watchdog_set_manage(cap_rights_watchdog_t *bit_field, bool val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xfffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 2U;
}

bool
cap_rights_watchdog_get_manage(const cap_rights_watchdog_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_watchdog_copy_manage(cap_rights_watchdog_t	    *bit_field_dst,
				const cap_rights_watchdog_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x4U;
}

void
cap_rights_watchdog_set_object_activate(cap_rights_watchdog_t *bit_field,
					bool		       val)
{
	uint32_t  bool_val = val ? (uint32_t)1 : (uint32_t)0;
	uint32_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint32_t)0x7fffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint32_t)0x1U) << 31U;
}

bool
cap_rights_watchdog_get_object_activate(const cap_rights_watchdog_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 31U) & (uint32_t)0x1U) << 0U;
	return val != (uint32_t)0;
}

void
cap_rights_watchdog_copy_object_activate(
	cap_rights_watchdog_t	    *bit_field_dst,
	const cap_rights_watchdog_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0x80000000U;
	bf_dst[0] |= bf_src[0] & (uint32_t)0x80000000U;
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

hyp_api_flags0_t
hyp_api_flags0_clean(hyp_api_flags0_t bit_field)
{
	return (hyp_api_flags0_t){ .bf = {
					   // (0x10006fffU &
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
hyp_api_flags0_is_clean(hyp_api_flags0_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

bool
hyp_api_flags0_get_trace_profile(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 12U) & (uint64_t)0x1U) << 0U;
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

	val |= ((bf[0] >> 15U) & (uint64_t)0x1U) << 0U;
	val |= ((bf[0] >> 17U) & (uint64_t)0x7ffU) << 1U;
	val |= ((bf[0] >> 32U) & (uint64_t)0xffffffffU) << 12U;
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
hyp_api_flags0_get_power(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 14U) & (uint64_t)0x1U) << 0U;
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
hyp_api_flags0_get_vpci(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 13U) & (uint64_t)0x1U) << 0U;
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
hyp_api_flags0_get_watchdog(const hyp_api_flags0_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint64_t)0x1U) << 0U;
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

hyp_api_flags1_t
hyp_api_flags1_clean(hyp_api_flags1_t bit_field)
{
	return (hyp_api_flags1_t){ .bf = {
					   // (0x2U & ~0x7U) |
					   (uint64_t)(0x0U) |
						   (bit_field.bf[0] & 0x7U),
				   } };
}

bool
hyp_api_flags1_is_equal(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	return ((b1.bf[0] & 0x7U) == (b2.bf[0] & 0x7U));
}

bool
hyp_api_flags1_is_empty(hyp_api_flags1_t bit_field)
{
	return ((bit_field.bf[0] & 0x7U) == 0U);
}

bool
hyp_api_flags1_is_clean(hyp_api_flags1_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffff8U) == 0x0U);
}

hyp_api_flags1_t
hyp_api_flags1_union(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	return (hyp_api_flags1_t){ .bf = {
					   b1.bf[0] | b2.bf[0],
				   } };
}

hyp_api_flags1_t
hyp_api_flags1_intersection(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	return (hyp_api_flags1_t){ .bf = {
					   b1.bf[0] & b2.bf[0],
				   } };
}

hyp_api_flags1_t
hyp_api_flags1_inverse(hyp_api_flags1_t b)
{
	return (hyp_api_flags1_t){ .bf = {
					   (uint64_t)~b.bf[0],
				   } };
}

hyp_api_flags1_t
hyp_api_flags1_difference(hyp_api_flags1_t b1, hyp_api_flags1_t b2)
{
	hyp_api_flags1_t not_b2 = hyp_api_flags1_inverse(b2);
	return hyp_api_flags1_intersection(b1, not_b2);
}

hyp_api_flags1_t
hyp_api_flags1_atomic_union(_Atomic hyp_api_flags1_t *b1, hyp_api_flags1_t b2,
			    memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return hyp_api_flags1_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	hyp_api_flags1_t old_value = atomic_load_explicit(b1, load_order);
	hyp_api_flags1_t new_value;

	do {
		new_value = hyp_api_flags1_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

hyp_api_flags1_t
hyp_api_flags1_atomic_intersection(_Atomic hyp_api_flags1_t *b1,
				   hyp_api_flags1_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	hyp_api_flags1_t not_b2 = hyp_api_flags1_inverse(b2);
	return hyp_api_flags1_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	hyp_api_flags1_t old_value = atomic_load_explicit(b1, load_order);
	hyp_api_flags1_t new_value;

	do {
		new_value = hyp_api_flags1_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

hyp_api_flags1_t
hyp_api_flags1_atomic_difference(_Atomic hyp_api_flags1_t *b1,
				 hyp_api_flags1_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return hyp_api_flags1_cast(ret_u);

#else
	hyp_api_flags1_t not_b2 = hyp_api_flags1_inverse(b2);
	return hyp_api_flags1_atomic_intersection(b1, not_b2, order);
#endif
}

bool
hyp_api_flags1_get_arm_v82_sve(const hyp_api_flags1_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags1_get_vgic_ext_spis(const hyp_api_flags1_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

bool
hyp_api_flags1_get_vgic_ext_ppis(const hyp_api_flags1_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
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

bool
hyp_api_flags2_is_clean(hyp_api_flags2_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
hyp_api_info_init(hyp_api_info_t *bit_field)
{
	*bit_field = hyp_api_info_default();
}

uint64_t
hyp_api_info_raw(hyp_api_info_t bit_field)
{
	return bit_field.bf[0];
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

bool
hyp_api_info_is_clean(hyp_api_info_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffffff0000U) == 0x0U);
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
memextent_access_attrs_init(memextent_access_attrs_t *bit_field)
{
	*bit_field = memextent_access_attrs_default();
}

uint32_t
memextent_access_attrs_raw(memextent_access_attrs_t bit_field)
{
	return bit_field.bf[0];
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

bool
memextent_access_attrs_is_clean(memextent_access_attrs_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
memextent_attrs_init(memextent_attrs_t *bit_field)
{
	*bit_field = memextent_attrs_default();
}

uint32_t
memextent_attrs_raw(memextent_attrs_t bit_field)
{
	return bit_field.bf[0];
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

bool
memextent_attrs_is_clean(memextent_attrs_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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

uint64_t
memextent_attrs_get_res_0(const memextent_attrs_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint32_t)0x1fU) << 0U;
	val |= ((bf[0] >> 10U) & (uint32_t)0x3fU) << 5U;
	val |= ((bf[0] >> 18U) & (uint32_t)0x3fffU) << 11U;
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

bool
memextent_donate_options_is_clean(memextent_donate_options_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
memextent_mapping_attrs_init(memextent_mapping_attrs_t *bit_field)
{
	*bit_field = memextent_mapping_attrs_default();
}

uint32_t
memextent_mapping_attrs_raw(memextent_mapping_attrs_t bit_field)
{
	return bit_field.bf[0];
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

bool
memextent_mapping_attrs_is_clean(memextent_mapping_attrs_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
memextent_modify_flags_init(memextent_modify_flags_t *bit_field)
{
	*bit_field = memextent_modify_flags_default();
}

uint32_t
memextent_modify_flags_raw(memextent_modify_flags_t bit_field)
{
	return bit_field.bf[0];
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

bool
memextent_modify_flags_is_clean(memextent_modify_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
msgqueue_create_info_init(msgqueue_create_info_t *bit_field)
{
	*bit_field = msgqueue_create_info_default();
}

uint64_t
msgqueue_create_info_raw(msgqueue_create_info_t bit_field)
{
	return bit_field.bf[0];
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

bool
msgqueue_create_info_is_clean(msgqueue_create_info_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffff00000000U) == 0x0U);
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
						(uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return msgqueue_send_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	msgqueue_send_flags_t old_value = atomic_load_explicit(b1, load_order);
	msgqueue_send_flags_t new_value;

	do {
		new_value = msgqueue_send_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

msgqueue_send_flags_t
msgqueue_send_flags_atomic_intersection(_Atomic msgqueue_send_flags_t *b1,
					msgqueue_send_flags_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	msgqueue_send_flags_t not_b2 = msgqueue_send_flags_inverse(b2);
	return msgqueue_send_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	msgqueue_send_flags_t old_value = atomic_load_explicit(b1, load_order);
	msgqueue_send_flags_t new_value;

	do {
		new_value = msgqueue_send_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

msgqueue_send_flags_t
msgqueue_send_flags_atomic_difference(_Atomic msgqueue_send_flags_t *b1,
				      msgqueue_send_flags_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return msgqueue_send_flags_cast(ret_u);

#else
	msgqueue_send_flags_t not_b2 = msgqueue_send_flags_inverse(b2);
	return msgqueue_send_flags_atomic_intersection(b1, not_b2, order);
#endif
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
partition_donate_flags_init(partition_donate_flags_t *bit_field)
{
	*bit_field = partition_donate_flags_default();
}

uint32_t
partition_donate_flags_raw(partition_donate_flags_t bit_field)
{
	return bit_field.bf[0];
}

partition_donate_flags_t
partition_donate_flags_clean(partition_donate_flags_t bit_field)
{
	return (partition_donate_flags_t){ .bf = {
						   (bit_field.bf[0] &
						    0xffffffffU),
					   } };
}

bool
partition_donate_flags_is_equal(partition_donate_flags_t b1,
				partition_donate_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

bool
partition_donate_flags_is_clean(partition_donate_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
partition_donate_flags_set_type(partition_donate_flags_t *bit_field,
				partition_donate_type_t	  val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff00U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffU) << 0U;
}

partition_donate_type_t
partition_donate_flags_get_type(const partition_donate_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffU) << 0U;
	return (partition_donate_type_t)val;
}

void
partition_donate_flags_copy_type(partition_donate_flags_t	*bit_field_dst,
				 const partition_donate_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffU;
}

uint32_t
partition_donate_flags_get_res0(const partition_donate_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0xffffffU) << 0U;
	return (uint32_t)val;
}

void
partition_query_flags_init(partition_query_flags_t *bit_field)
{
	*bit_field = partition_query_flags_default();
}

uint32_t
partition_query_flags_raw(partition_query_flags_t bit_field)
{
	return bit_field.bf[0];
}

partition_query_flags_t
partition_query_flags_clean(partition_query_flags_t bit_field)
{
	return (partition_query_flags_t){ .bf = {
						  (bit_field.bf[0] &
						   0xffffffffU),
					  } };
}

bool
partition_query_flags_is_equal(partition_query_flags_t b1,
			       partition_query_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffU) == (b2.bf[0] & 0xffffffffU));
}

bool
partition_query_flags_is_clean(partition_query_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
partition_query_flags_set_type(partition_query_flags_t *bit_field,
			       partition_query_type_t	val)
{
	uint32_t *bf = &bit_field->bf[0];
	bf[0] &= (uint32_t)0xffffff00U;
	bf[0] |= (((uint32_t)val >> 0U) & (uint32_t)0xffU) << 0U;
}

partition_query_type_t
partition_query_flags_get_type(const partition_query_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint32_t)0xffU) << 0U;
	return (partition_query_type_t)val;
}

void
partition_query_flags_copy_type(partition_query_flags_t	      *bit_field_dst,
				const partition_query_flags_t *bit_field_src)
{
	uint32_t       *bf_dst = (uint32_t *)&bit_field_dst->bf[0];
	const uint32_t *bf_src = (const uint32_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint32_t)0xffU;
	bf_dst[0] |= bf_src[0] & (uint32_t)0xffU;
}

uint32_t
partition_query_flags_get_res0(const partition_query_flags_t *bit_field)
{
	uint32_t	val = 0;
	const uint32_t *bf  = (const uint32_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint32_t)0xffffffU) << 0U;
	return (uint32_t)val;
}

void
pci_capability_access_flags_init(pci_capability_access_flags_t *bit_field)
{
	*bit_field = pci_capability_access_flags_default();
}

uint64_t
pci_capability_access_flags_raw(pci_capability_access_flags_t bit_field)
{
	return bit_field.bf[0];
}

pci_capability_access_flags_t
pci_capability_access_flags_clean(pci_capability_access_flags_t bit_field)
{
	return (pci_capability_access_flags_t){ .bf = {
							(bit_field.bf[0] & 0xfU),
						} };
}

bool
pci_capability_access_flags_is_equal(pci_capability_access_flags_t b1,
				     pci_capability_access_flags_t b2)
{
	return ((b1.bf[0] & 0xfU) == (b2.bf[0] & 0xfU));
}

bool
pci_capability_access_flags_is_empty(pci_capability_access_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfU) == 0U);
}

bool
pci_capability_access_flags_is_clean(pci_capability_access_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffff0U) == 0x0U);
}

pci_capability_access_flags_t
pci_capability_access_flags_union(pci_capability_access_flags_t b1,
				  pci_capability_access_flags_t b2)
{
	return (pci_capability_access_flags_t){ .bf = {
							b1.bf[0] | b2.bf[0],
						} };
}

pci_capability_access_flags_t
pci_capability_access_flags_intersection(pci_capability_access_flags_t b1,
					 pci_capability_access_flags_t b2)
{
	return (pci_capability_access_flags_t){ .bf = {
							b1.bf[0] & b2.bf[0],
						} };
}

pci_capability_access_flags_t
pci_capability_access_flags_inverse(pci_capability_access_flags_t b)
{
	return (pci_capability_access_flags_t){ .bf = {
							(uint64_t)~b.bf[0],
						} };
}

pci_capability_access_flags_t
pci_capability_access_flags_difference(pci_capability_access_flags_t b1,
				       pci_capability_access_flags_t b2)
{
	pci_capability_access_flags_t not_b2 =
		pci_capability_access_flags_inverse(b2);
	return pci_capability_access_flags_intersection(b1, not_b2);
}

pci_capability_access_flags_t
pci_capability_access_flags_atomic_union(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_capability_access_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_capability_access_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_capability_access_flags_t new_value;

	do {
		new_value = pci_capability_access_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_capability_access_flags_t
pci_capability_access_flags_atomic_intersection(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	pci_capability_access_flags_t not_b2 =
		pci_capability_access_flags_inverse(b2);
	return pci_capability_access_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_capability_access_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_capability_access_flags_t new_value;

	do {
		new_value =
			pci_capability_access_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_capability_access_flags_t
pci_capability_access_flags_atomic_difference(
	_Atomic pci_capability_access_flags_t *b1,
	pci_capability_access_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_capability_access_flags_cast(ret_u);

#else
	pci_capability_access_flags_t not_b2 =
		pci_capability_access_flags_inverse(b2);
	return pci_capability_access_flags_atomic_intersection(b1, not_b2,
							       order);
#endif
}

void
pci_capability_access_flags_set_passthrough_visible(
	pci_capability_access_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
pci_capability_access_flags_get_passthrough_visible(
	const pci_capability_access_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_capability_access_flags_copy_passthrough_visible(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
pci_capability_access_flags_set_passthrough_writable(
	pci_capability_access_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
pci_capability_access_flags_get_passthrough_writable(
	const pci_capability_access_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_capability_access_flags_copy_passthrough_writable(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
pci_capability_access_flags_set_lockdown_visible(
	pci_capability_access_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 2U;
}

bool
pci_capability_access_flags_get_lockdown_visible(
	const pci_capability_access_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_capability_access_flags_copy_lockdown_visible(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x4U;
}

void
pci_capability_access_flags_set_lockdown_writable(
	pci_capability_access_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
pci_capability_access_flags_get_lockdown_writable(
	const pci_capability_access_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_capability_access_flags_copy_lockdown_writable(
	pci_capability_access_flags_t	    *bit_field_dst,
	const pci_capability_access_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
pci_function_option_flags_init(pci_function_option_flags_t *bit_field)
{
	*bit_field = pci_function_option_flags_default();
}

uint64_t
pci_function_option_flags_raw(pci_function_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

pci_function_option_flags_t
pci_function_option_flags_clean(pci_function_option_flags_t bit_field)
{
	return (pci_function_option_flags_t){ .bf = {
						      (bit_field.bf[0] & 0x3U),
					      } };
}

bool
pci_function_option_flags_is_equal(pci_function_option_flags_t b1,
				   pci_function_option_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
pci_function_option_flags_is_empty(pci_function_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
pci_function_option_flags_is_clean(pci_function_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

pci_function_option_flags_t
pci_function_option_flags_union(pci_function_option_flags_t b1,
				pci_function_option_flags_t b2)
{
	return (pci_function_option_flags_t){ .bf = {
						      b1.bf[0] | b2.bf[0],
					      } };
}

pci_function_option_flags_t
pci_function_option_flags_intersection(pci_function_option_flags_t b1,
				       pci_function_option_flags_t b2)
{
	return (pci_function_option_flags_t){ .bf = {
						      b1.bf[0] & b2.bf[0],
					      } };
}

pci_function_option_flags_t
pci_function_option_flags_inverse(pci_function_option_flags_t b)
{
	return (pci_function_option_flags_t){ .bf = {
						      (uint64_t)~b.bf[0],
					      } };
}

pci_function_option_flags_t
pci_function_option_flags_difference(pci_function_option_flags_t b1,
				     pci_function_option_flags_t b2)
{
	pci_function_option_flags_t not_b2 =
		pci_function_option_flags_inverse(b2);
	return pci_function_option_flags_intersection(b1, not_b2);
}

pci_function_option_flags_t
pci_function_option_flags_atomic_union(_Atomic pci_function_option_flags_t *b1,
				       pci_function_option_flags_t	    b2,
				       memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_function_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_function_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_function_option_flags_t new_value;

	do {
		new_value = pci_function_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_function_option_flags_t
pci_function_option_flags_atomic_intersection(
	_Atomic pci_function_option_flags_t *b1, pci_function_option_flags_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	pci_function_option_flags_t not_b2 =
		pci_function_option_flags_inverse(b2);
	return pci_function_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_function_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_function_option_flags_t new_value;

	do {
		new_value =
			pci_function_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_function_option_flags_t
pci_function_option_flags_atomic_difference(
	_Atomic pci_function_option_flags_t *b1, pci_function_option_flags_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_function_option_flags_cast(ret_u);

#else
	pci_function_option_flags_t not_b2 =
		pci_function_option_flags_inverse(b2);
	return pci_function_option_flags_atomic_intersection(b1, not_b2, order);
#endif
}

void
pci_function_option_flags_set_passthrough(
	pci_function_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
pci_function_option_flags_get_passthrough(
	const pci_function_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_function_option_flags_copy_passthrough(
	pci_function_option_flags_t	  *bit_field_dst,
	const pci_function_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
pci_function_option_flags_set_sr_iov_vf(pci_function_option_flags_t *bit_field,
					bool			     val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
pci_function_option_flags_get_sr_iov_vf(
	const pci_function_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_function_option_flags_copy_sr_iov_vf(
	pci_function_option_flags_t	  *bit_field_dst,
	const pci_function_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
pci_host_option_flags_init(pci_host_option_flags_t *bit_field)
{
	*bit_field = pci_host_option_flags_default();
}

uint64_t
pci_host_option_flags_raw(pci_host_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

pci_host_option_flags_t
pci_host_option_flags_clean(pci_host_option_flags_t bit_field)
{
	return (pci_host_option_flags_t){ .bf = {
						  // (0x1U & ~0x3U) |
						  (uint64_t)(0x0U) |
							  (bit_field.bf[0] &
							   0x3U),
					  } };
}

bool
pci_host_option_flags_is_equal(pci_host_option_flags_t b1,
			       pci_host_option_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
pci_host_option_flags_is_empty(pci_host_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
pci_host_option_flags_is_clean(pci_host_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

pci_host_option_flags_t
pci_host_option_flags_union(pci_host_option_flags_t b1,
			    pci_host_option_flags_t b2)
{
	return (pci_host_option_flags_t){ .bf = {
						  b1.bf[0] | b2.bf[0],
					  } };
}

pci_host_option_flags_t
pci_host_option_flags_intersection(pci_host_option_flags_t b1,
				   pci_host_option_flags_t b2)
{
	return (pci_host_option_flags_t){ .bf = {
						  b1.bf[0] & b2.bf[0],
					  } };
}

pci_host_option_flags_t
pci_host_option_flags_inverse(pci_host_option_flags_t b)
{
	return (pci_host_option_flags_t){ .bf = {
						  (uint64_t)~b.bf[0],
					  } };
}

pci_host_option_flags_t
pci_host_option_flags_difference(pci_host_option_flags_t b1,
				 pci_host_option_flags_t b2)
{
	pci_host_option_flags_t not_b2 = pci_host_option_flags_inverse(b2);
	return pci_host_option_flags_intersection(b1, not_b2);
}

pci_host_option_flags_t
pci_host_option_flags_atomic_union(_Atomic pci_host_option_flags_t *b1,
				   pci_host_option_flags_t	    b2,
				   memory_order			    order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_host_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_host_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_host_option_flags_t new_value;

	do {
		new_value = pci_host_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_host_option_flags_t
pci_host_option_flags_atomic_intersection(_Atomic pci_host_option_flags_t *b1,
					  pci_host_option_flags_t	   b2,
					  memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	pci_host_option_flags_t not_b2 = pci_host_option_flags_inverse(b2);
	return pci_host_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	pci_host_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	pci_host_option_flags_t new_value;

	do {
		new_value = pci_host_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

pci_host_option_flags_t
pci_host_option_flags_atomic_difference(_Atomic pci_host_option_flags_t *b1,
					pci_host_option_flags_t		 b2,
					memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return pci_host_option_flags_cast(ret_u);

#else
	pci_host_option_flags_t not_b2 = pci_host_option_flags_inverse(b2);
	return pci_host_option_flags_atomic_intersection(b1, not_b2, order);
#endif
}

void
pci_host_option_flags_set_pcie(pci_host_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
pci_host_option_flags_get_pcie(const pci_host_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_host_option_flags_copy_pcie(pci_host_option_flags_t	      *bit_field_dst,
				const pci_host_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
pci_host_option_flags_set_lockdown(pci_host_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
pci_host_option_flags_get_lockdown(const pci_host_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
pci_host_option_flags_copy_lockdown(pci_host_option_flags_t *bit_field_dst,
				    const pci_host_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
pci_responder_id_init(pci_responder_id_t *bit_field)
{
	*bit_field = pci_responder_id_default();
}

uint16_t
pci_responder_id_raw(pci_responder_id_t bit_field)
{
	return bit_field.bf[0];
}

pci_responder_id_t
pci_responder_id_clean(pci_responder_id_t bit_field)
{
	return (pci_responder_id_t){ .bf = {
					     (bit_field.bf[0] & 0xffffU),
				     } };
}

bool
pci_responder_id_is_equal(pci_responder_id_t b1, pci_responder_id_t b2)
{
	return ((b1.bf[0] & 0xffffU) == (b2.bf[0] & 0xffffU));
}

bool
pci_responder_id_is_clean(pci_responder_id_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
pci_responder_id_set_function(pci_responder_id_t *bit_field, index_t val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0xfff8U;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0x7U) << 0U;
}

index_t
pci_responder_id_get_function(const pci_responder_id_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint16_t)0x7U) << 0U;
	return (index_t)val;
}

void
pci_responder_id_copy_function(pci_responder_id_t	*bit_field_dst,
			       const pci_responder_id_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0x7U;
	bf_dst[0] |= bf_src[0] & (uint16_t)0x7U;
}

void
pci_responder_id_set_slot(pci_responder_id_t *bit_field, index_t val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0xff07U;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0x1fU) << 3U;
}

index_t
pci_responder_id_get_slot(const pci_responder_id_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint16_t)0x1fU) << 0U;
	return (index_t)val;
}

void
pci_responder_id_copy_slot(pci_responder_id_t	    *bit_field_dst,
			   const pci_responder_id_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0xf8U;
	bf_dst[0] |= bf_src[0] & (uint16_t)0xf8U;
}

void
pci_responder_id_set_bus(pci_responder_id_t *bit_field, index_t val)
{
	uint16_t *bf = &bit_field->bf[0];
	bf[0] &= (uint16_t)0xffU;
	bf[0] |= (((uint16_t)val >> 0U) & (uint16_t)0xffU) << 8U;
}

index_t
pci_responder_id_get_bus(const pci_responder_id_t *bit_field)
{
	uint16_t	val = 0;
	const uint16_t *bf  = (const uint16_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 8U) & (uint16_t)0xffU) << 0U;
	return (index_t)val;
}

void
pci_responder_id_copy_bus(pci_responder_id_t	   *bit_field_dst,
			  const pci_responder_id_t *bit_field_src)
{
	uint16_t       *bf_dst = (uint16_t *)&bit_field_dst->bf[0];
	const uint16_t *bf_src = (const uint16_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint16_t)0xff00U;
	bf_dst[0] |= bf_src[0] & (uint16_t)0xff00U;
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

root_env_mmio_range_properties_t
root_env_mmio_range_properties_clean(root_env_mmio_range_properties_t bit_field)
{
	return (root_env_mmio_range_properties_t){ .bf = {
							   (bit_field.bf[0] &
							    0xc000ff07ffffffffU),
						   } };
}

bool
root_env_mmio_range_properties_is_equal(root_env_mmio_range_properties_t b1,
					root_env_mmio_range_properties_t b2)
{
	return ((b1.bf[0] & 0xc000ff07ffffffffU) ==
		(b2.bf[0] & 0xc000ff07ffffffffU));
}

bool
root_env_mmio_range_properties_is_clean(
	root_env_mmio_range_properties_t bit_field)
{
	return ((bit_field.bf[0] & 0x3fff00f800000000U) == 0x0U);
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
root_env_mmio_range_properties_set_pvm_unmapped(
	root_env_mmio_range_properties_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xbfffffffffffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 62U;
}

bool
root_env_mmio_range_properties_get_pvm_unmapped(
	const root_env_mmio_range_properties_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 62U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
root_env_mmio_range_properties_copy_pvm_unmapped(
	root_env_mmio_range_properties_t       *bit_field_dst,
	const root_env_mmio_range_properties_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x4000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x4000000000000000U;
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

bool
scheduler_yield_control_is_clean(scheduler_yield_control_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fff0000U) == 0x0U);
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
sdei_error_flags_init(sdei_error_flags_t *bit_field)
{
	*bit_field = sdei_error_flags_default();
}

uint64_t
sdei_error_flags_raw(sdei_error_flags_t bit_field)
{
	return bit_field.bf[0];
}

sdei_error_flags_t
sdei_error_flags_clean(sdei_error_flags_t bit_field)
{
	return (sdei_error_flags_t){ .bf = {
					     (bit_field.bf[0] &
					      0xffffffffffffffffU),
				     } };
}

bool
sdei_error_flags_is_equal(sdei_error_flags_t b1, sdei_error_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
sdei_error_flags_is_clean(sdei_error_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
sdei_error_flags_set_reason(sdei_error_flags_t *bit_field,
			    sdei_error_reason_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffff00000000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffffffU) << 0U;
}

sdei_error_reason_t
sdei_error_flags_get_reason(const sdei_error_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffU) << 0U;
	return (sdei_error_reason_t)val;
}

void
sdei_error_flags_copy_reason(sdei_error_flags_t	      *bit_field_dst,
			     const sdei_error_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffffU;
}

uint32_t
sdei_error_flags_get_res0(const sdei_error_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 32U) & (uint64_t)0x7fffffffU) << 0U;
	return (uint32_t)val;
}

void
sdei_error_flags_set_system_error(sdei_error_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x7fffffffffffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 63U;
}

bool
sdei_error_flags_get_system_error(const sdei_error_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 63U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
sdei_error_flags_copy_system_error(sdei_error_flags_t	    *bit_field_dst,
				   const sdei_error_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8000000000000000U;
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

bool
smccc_function_id_is_clean(smccc_function_id_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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

bool
smccc_vendor_hyp_function_id_is_clean(smccc_vendor_hyp_function_id_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
vcpu_option_flags_init(vcpu_option_flags_t *bit_field)
{
	*bit_field = vcpu_option_flags_default();
}

uint64_t
vcpu_option_flags_raw(vcpu_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

vcpu_option_flags_t
vcpu_option_flags_clean(vcpu_option_flags_t bit_field)
{
	return (vcpu_option_flags_t){ .bf = {
					      (bit_field.bf[0] &
					       0x8000000000000fbfU),
				      } };
}

bool
vcpu_option_flags_is_equal(vcpu_option_flags_t b1, vcpu_option_flags_t b2)
{
	return ((b1.bf[0] & 0x8000000000000fbfU) ==
		(b2.bf[0] & 0x8000000000000fbfU));
}

bool
vcpu_option_flags_is_empty(vcpu_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x8000000000000fbfU) == 0U);
}

bool
vcpu_option_flags_is_clean(vcpu_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x7ffffffffffff040U) == 0x0U);
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
					      (uint64_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_option_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_option_flags_t new_value;

	do {
		new_value = vcpu_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_option_flags_t
vcpu_option_flags_atomic_intersection(_Atomic vcpu_option_flags_t *b1,
				      vcpu_option_flags_t	   b2,
				      memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vcpu_option_flags_t not_b2 = vcpu_option_flags_inverse(b2);
	return vcpu_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_option_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_option_flags_t new_value;

	do {
		new_value = vcpu_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_option_flags_t
vcpu_option_flags_atomic_difference(_Atomic vcpu_option_flags_t *b1,
				    vcpu_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_option_flags_cast(ret_u);

#else
	vcpu_option_flags_t not_b2 = vcpu_option_flags_inverse(b2);
	return vcpu_option_flags_atomic_intersection(b1, not_b2, order);
#endif
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
vcpu_option_flags_set_sme_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffbffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 10U;
}

bool
vcpu_option_flags_get_sme_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 10U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_sme_allowed(vcpu_option_flags_t	     *bit_field_dst,
				   const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x400U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x400U;
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
vcpu_option_flags_set_sdei_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffff7ffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 11U;
}

bool
vcpu_option_flags_get_sdei_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 11U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_sdei_allowed(vcpu_option_flags_t	      *bit_field_dst,
				    const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x800U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x800U;
}

void
vcpu_option_flags_set_mpam_allowed(vcpu_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffff7fU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 7U;
}

bool
vcpu_option_flags_get_mpam_allowed(const vcpu_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vcpu_option_flags_copy_mpam_allowed(vcpu_option_flags_t	      *bit_field_dst,
				    const vcpu_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x80U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x80U;
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
vcpu_poweroff_flags_init(vcpu_poweroff_flags_t *bit_field)
{
	*bit_field = vcpu_poweroff_flags_default();
}

uint64_t
vcpu_poweroff_flags_raw(vcpu_poweroff_flags_t bit_field)
{
	return bit_field.bf[0];
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
						(uint64_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_poweroff_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_poweroff_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_poweroff_flags_t new_value;

	do {
		new_value = vcpu_poweroff_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_intersection(_Atomic vcpu_poweroff_flags_t *b1,
					vcpu_poweroff_flags_t	       b2,
					memory_order		       order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vcpu_poweroff_flags_t not_b2 = vcpu_poweroff_flags_inverse(b2);
	return vcpu_poweroff_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_poweroff_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_poweroff_flags_t new_value;

	do {
		new_value = vcpu_poweroff_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_poweroff_flags_t
vcpu_poweroff_flags_atomic_difference(_Atomic vcpu_poweroff_flags_t *b1,
				      vcpu_poweroff_flags_t	     b2,
				      memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_poweroff_flags_cast(ret_u);

#else
	vcpu_poweroff_flags_t not_b2 = vcpu_poweroff_flags_inverse(b2);
	return vcpu_poweroff_flags_atomic_intersection(b1, not_b2, order);
#endif
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
vcpu_poweron_flags_init(vcpu_poweron_flags_t *bit_field)
{
	*bit_field = vcpu_poweron_flags_default();
}

uint64_t
vcpu_poweron_flags_raw(vcpu_poweron_flags_t bit_field)
{
	return bit_field.bf[0];
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
					       (uint64_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_poweron_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_poweron_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_poweron_flags_t new_value;

	do {
		new_value = vcpu_poweron_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_intersection(_Atomic vcpu_poweron_flags_t *b1,
				       vcpu_poweron_flags_t	     b2,
				       memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vcpu_poweron_flags_t not_b2 = vcpu_poweron_flags_inverse(b2);
	return vcpu_poweron_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_poweron_flags_t old_value = atomic_load_explicit(b1, load_order);
	vcpu_poweron_flags_t new_value;

	do {
		new_value = vcpu_poweron_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_poweron_flags_t
vcpu_poweron_flags_atomic_difference(_Atomic vcpu_poweron_flags_t *b1,
				     vcpu_poweron_flags_t	   b2,
				     memory_order		   order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_poweron_flags_cast(ret_u);

#else
	vcpu_poweron_flags_t not_b2 = vcpu_poweron_flags_inverse(b2);
	return vcpu_poweron_flags_atomic_intersection(b1, not_b2, order);
#endif
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
						    (uint32_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and set, release order
		__asm__ volatile("ldsetl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_run_poweroff_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_run_poweroff_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vcpu_run_poweroff_flags_t new_value;

	do {
		new_value = vcpu_run_poweroff_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_intersection(
	_Atomic vcpu_run_poweroff_flags_t *b1, vcpu_run_poweroff_flags_t b2,
	memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vcpu_run_poweroff_flags_t not_b2 = vcpu_run_poweroff_flags_inverse(b2);
	return vcpu_run_poweroff_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vcpu_run_poweroff_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vcpu_run_poweroff_flags_t new_value;

	do {
		new_value = vcpu_run_poweroff_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vcpu_run_poweroff_flags_t
vcpu_run_poweroff_flags_atomic_difference(_Atomic vcpu_run_poweroff_flags_t *b1,
					  vcpu_run_poweroff_flags_t	     b2,
					  memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint32_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 32-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 32-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 32-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 32-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vcpu_run_poweroff_flags_cast(ret_u);

#else
	vcpu_run_poweroff_flags_t not_b2 = vcpu_run_poweroff_flags_inverse(b2);
	return vcpu_run_poweroff_flags_atomic_intersection(b1, not_b2, order);
#endif
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
vgic_gicr_attach_flags_init(vgic_gicr_attach_flags_t *bit_field)
{
	*bit_field = vgic_gicr_attach_flags_default();
}

uint64_t
vgic_gicr_attach_flags_raw(vgic_gicr_attach_flags_t bit_field)
{
	return bit_field.bf[0];
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
						   (uint64_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vgic_gicr_attach_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vgic_gicr_attach_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vgic_gicr_attach_flags_t new_value;

	do {
		new_value = vgic_gicr_attach_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_intersection(_Atomic vgic_gicr_attach_flags_t *b1,
					   vgic_gicr_attach_flags_t	     b2,
					   memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vgic_gicr_attach_flags_t not_b2 = vgic_gicr_attach_flags_inverse(b2);
	return vgic_gicr_attach_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vgic_gicr_attach_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vgic_gicr_attach_flags_t new_value;

	do {
		new_value = vgic_gicr_attach_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vgic_gicr_attach_flags_t
vgic_gicr_attach_flags_atomic_difference(_Atomic vgic_gicr_attach_flags_t *b1,
					 vgic_gicr_attach_flags_t	   b2,
					 memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vgic_gicr_attach_flags_cast(ret_u);

#else
	vgic_gicr_attach_flags_t not_b2 = vgic_gicr_attach_flags_inverse(b2);
	return vgic_gicr_attach_flags_atomic_intersection(b1, not_b2, order);
#endif
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
vic_msi_source_config_init(vic_msi_source_config_t *bit_field)
{
	*bit_field = vic_msi_source_config_default();
}

uint64_t
vic_msi_source_config_raw(vic_msi_source_config_t bit_field)
{
	return bit_field.bf[0];
}

vic_msi_source_config_t
vic_msi_source_config_clean(vic_msi_source_config_t bit_field)
{
	return (vic_msi_source_config_t){ .bf = {
						  (bit_field.bf[0] &
						   0xffffffffffffffffU),
					  } };
}

bool
vic_msi_source_config_is_equal(vic_msi_source_config_t b1,
			       vic_msi_source_config_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
vic_msi_source_config_is_clean(vic_msi_source_config_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
vic_msi_source_config_set_index(vic_msi_source_config_t *bit_field,
				uint16_t		 val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffff0000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffU) << 0U;
}

uint16_t
vic_msi_source_config_get_index(const vic_msi_source_config_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffU) << 0U;
	return (uint16_t)val;
}

void
vic_msi_source_config_copy_index(vic_msi_source_config_t       *bit_field_dst,
				 const vic_msi_source_config_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffU;
}

uint64_t
vic_msi_source_config_get_res0(const vic_msi_source_config_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0xffffffffffffU) << 0U;
	return (uint64_t)val;
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

bool
vic_option_flags_is_clean(vic_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
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
virtio_backend_interface_type_init(virtio_backend_interface_type_t *bit_field)
{
	*bit_field = virtio_backend_interface_type_default();
}

uint64_t
virtio_backend_interface_type_raw(virtio_backend_interface_type_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_interface_type_t
virtio_backend_interface_type_clean(virtio_backend_interface_type_t bit_field)
{
	return (virtio_backend_interface_type_t){ .bf = {
							  (bit_field.bf[0] &
							   0xff00ffU),
						  } };
}

bool
virtio_backend_interface_type_is_equal(virtio_backend_interface_type_t b1,
				       virtio_backend_interface_type_t b2)
{
	return ((b1.bf[0] & 0xff00ffU) == (b2.bf[0] & 0xff00ffU));
}

bool
virtio_backend_interface_type_is_clean(virtio_backend_interface_type_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffffff00ff00U) == 0x0U);
}

void
virtio_backend_interface_type_set_transport(
	virtio_backend_interface_type_t *bit_field, virtio_transport_type_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffff00ffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffU) << 16U;
}

virtio_transport_type_t
virtio_backend_interface_type_get_transport(
	const virtio_backend_interface_type_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0xffU) << 0U;
	return (virtio_transport_type_t)val;
}

void
virtio_backend_interface_type_copy_transport(
	virtio_backend_interface_type_t	      *bit_field_dst,
	const virtio_backend_interface_type_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xff0000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xff0000U;
}

void
virtio_backend_interface_type_set_device(
	virtio_backend_interface_type_t *bit_field, virtio_device_type_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffff00U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffU) << 0U;
}

virtio_device_type_t
virtio_backend_interface_type_get_device(
	const virtio_backend_interface_type_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffU) << 0U;
	return (virtio_device_type_t)val;
}

void
virtio_backend_interface_type_copy_device(
	virtio_backend_interface_type_t	      *bit_field_dst,
	const virtio_backend_interface_type_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffU;
}

void
virtio_backend_interrupt_perqueue_init(
	virtio_backend_interrupt_perqueue_t *bit_field)
{
	*bit_field = virtio_backend_interrupt_perqueue_default();
}

uint64_t
virtio_backend_interrupt_perqueue_raw(
	virtio_backend_interrupt_perqueue_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_interrupt_perqueue_t
virtio_backend_interrupt_perqueue_clean(
	virtio_backend_interrupt_perqueue_t bit_field)
{
	return (virtio_backend_interrupt_perqueue_t){ .bf = {
							      (bit_field.bf[0] &
							       0x800000000000ffffU),
						      } };
}

bool
virtio_backend_interrupt_perqueue_is_equal(
	virtio_backend_interrupt_perqueue_t b1,
	virtio_backend_interrupt_perqueue_t b2)
{
	return ((b1.bf[0] & 0x800000000000ffffU) ==
		(b2.bf[0] & 0x800000000000ffffU));
}

bool
virtio_backend_interrupt_perqueue_is_clean(
	virtio_backend_interrupt_perqueue_t bit_field)
{
	return ((bit_field.bf[0] & 0x7fffffffffff0000U) == 0x0U);
}

void
virtio_backend_interrupt_perqueue_set_queues_ready(
	virtio_backend_interrupt_perqueue_t *bit_field, uint64_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffff0000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffU) << 0U;
}

uint64_t
virtio_backend_interrupt_perqueue_get_queues_ready(
	const virtio_backend_interrupt_perqueue_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffU) << 0U;
	return (uint64_t)val;
}

void
virtio_backend_interrupt_perqueue_copy_queues_ready(
	virtio_backend_interrupt_perqueue_t	  *bit_field_dst,
	const virtio_backend_interrupt_perqueue_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffU;
}

void
virtio_backend_interrupt_perqueue_set_config_update(
	virtio_backend_interrupt_perqueue_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0x7fffffffffffffffU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 63U;
}

bool
virtio_backend_interrupt_perqueue_get_config_update(
	const virtio_backend_interrupt_perqueue_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 63U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_interrupt_perqueue_copy_config_update(
	virtio_backend_interrupt_perqueue_t	  *bit_field_dst,
	const virtio_backend_interrupt_perqueue_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8000000000000000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8000000000000000U;
}

void
virtio_backend_memextent_layout_init(
	virtio_backend_memextent_layout_t *bit_field)
{
	*bit_field = virtio_backend_memextent_layout_default();
}

uint64_t
virtio_backend_memextent_layout_raw(virtio_backend_memextent_layout_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_memextent_layout_t
virtio_backend_memextent_layout_clean(
	virtio_backend_memextent_layout_t bit_field)
{
	return (virtio_backend_memextent_layout_t){ .bf = {
							    (bit_field.bf[0] &
							     0x1ffffffffU),
						    } };
}

bool
virtio_backend_memextent_layout_is_equal(virtio_backend_memextent_layout_t b1,
					 virtio_backend_memextent_layout_t b2)
{
	return ((b1.bf[0] & 0x1ffffffffU) == (b2.bf[0] & 0x1ffffffffU));
}

bool
virtio_backend_memextent_layout_is_clean(
	virtio_backend_memextent_layout_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffe00000000U) == 0x0U);
}

void
virtio_backend_memextent_layout_set_devcfg_offset(
	virtio_backend_memextent_layout_t *bit_field, size_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffe0000ffffU;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0x1ffffU) << 16U;
}

size_t
virtio_backend_memextent_layout_get_devcfg_offset(
	const virtio_backend_memextent_layout_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 16U) & (uint64_t)0x1ffffU) << 0U;
	return (size_t)val;
}

void
virtio_backend_memextent_layout_copy_devcfg_offset(
	virtio_backend_memextent_layout_t	*bit_field_dst,
	const virtio_backend_memextent_layout_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1ffff0000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1ffff0000U;
}

void
virtio_backend_memextent_layout_set_devcfg_size(
	virtio_backend_memextent_layout_t *bit_field, size_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffff0000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffU) << 0U;
}

size_t
virtio_backend_memextent_layout_get_devcfg_size(
	const virtio_backend_memextent_layout_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffU) << 0U;
	return (size_t)val;
}

void
virtio_backend_memextent_layout_copy_devcfg_size(
	virtio_backend_memextent_layout_t	*bit_field_dst,
	const virtio_backend_memextent_layout_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffU;
}

void
virtio_backend_notify_flags_init(virtio_backend_notify_flags_t *bit_field)
{
	*bit_field = virtio_backend_notify_flags_default();
}

uint64_t
virtio_backend_notify_flags_raw(virtio_backend_notify_flags_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_clean(virtio_backend_notify_flags_t bit_field)
{
	return (virtio_backend_notify_flags_t){ .bf = {
							// (0x1U & ~0x3U) |
							(uint64_t)(0x0U) |
								(bit_field.bf[0] &
								 0x3U),
						} };
}

bool
virtio_backend_notify_flags_is_equal(virtio_backend_notify_flags_t b1,
				     virtio_backend_notify_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
virtio_backend_notify_flags_is_empty(virtio_backend_notify_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
virtio_backend_notify_flags_is_clean(virtio_backend_notify_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_union(virtio_backend_notify_flags_t b1,
				  virtio_backend_notify_flags_t b2)
{
	return (virtio_backend_notify_flags_t){ .bf = {
							b1.bf[0] | b2.bf[0],
						} };
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_intersection(virtio_backend_notify_flags_t b1,
					 virtio_backend_notify_flags_t b2)
{
	return (virtio_backend_notify_flags_t){ .bf = {
							b1.bf[0] & b2.bf[0],
						} };
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_inverse(virtio_backend_notify_flags_t b)
{
	return (virtio_backend_notify_flags_t){ .bf = {
							(uint64_t)~b.bf[0],
						} };
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_difference(virtio_backend_notify_flags_t b1,
				       virtio_backend_notify_flags_t b2)
{
	virtio_backend_notify_flags_t not_b2 =
		virtio_backend_notify_flags_inverse(b2);
	return virtio_backend_notify_flags_intersection(b1, not_b2);
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_union(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_notify_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_notify_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_notify_flags_t new_value;

	do {
		new_value = virtio_backend_notify_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_intersection(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	virtio_backend_notify_flags_t not_b2 =
		virtio_backend_notify_flags_inverse(b2);
	return virtio_backend_notify_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_notify_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_notify_flags_t new_value;

	do {
		new_value =
			virtio_backend_notify_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_notify_flags_t
virtio_backend_notify_flags_atomic_difference(
	_Atomic virtio_backend_notify_flags_t *b1,
	virtio_backend_notify_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_notify_flags_cast(ret_u);

#else
	virtio_backend_notify_flags_t not_b2 =
		virtio_backend_notify_flags_inverse(b2);
	return virtio_backend_notify_flags_atomic_intersection(b1, not_b2,
							       order);
#endif
}

void
virtio_backend_notify_flags_set_per_queue(
	virtio_backend_notify_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
virtio_backend_notify_flags_get_per_queue(
	const virtio_backend_notify_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_flags_copy_per_queue(
	virtio_backend_notify_flags_t	    *bit_field_dst,
	const virtio_backend_notify_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
virtio_backend_notify_flags_set_config_update(
	virtio_backend_notify_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
virtio_backend_notify_flags_get_config_update(
	const virtio_backend_notify_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_flags_copy_config_update(
	virtio_backend_notify_flags_t	    *bit_field_dst,
	const virtio_backend_notify_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
virtio_backend_notify_reason_init(virtio_backend_notify_reason_t *bit_field)
{
	*bit_field = virtio_backend_notify_reason_default();
}

uint64_t
virtio_backend_notify_reason_raw(virtio_backend_notify_reason_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_clean(virtio_backend_notify_reason_t bit_field)
{
	return (virtio_backend_notify_reason_t){ .bf = {
							 (bit_field.bf[0] &
							  0x1fU),
						 } };
}

bool
virtio_backend_notify_reason_is_equal(virtio_backend_notify_reason_t b1,
				      virtio_backend_notify_reason_t b2)
{
	return ((b1.bf[0] & 0x1fU) == (b2.bf[0] & 0x1fU));
}

bool
virtio_backend_notify_reason_is_empty(virtio_backend_notify_reason_t bit_field)
{
	return ((bit_field.bf[0] & 0x1fU) == 0U);
}

bool
virtio_backend_notify_reason_is_clean(virtio_backend_notify_reason_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffffffffffe0U) == 0x0U);
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_union(virtio_backend_notify_reason_t b1,
				   virtio_backend_notify_reason_t b2)
{
	return (virtio_backend_notify_reason_t){ .bf = {
							 b1.bf[0] | b2.bf[0],
						 } };
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_intersection(virtio_backend_notify_reason_t b1,
					  virtio_backend_notify_reason_t b2)
{
	return (virtio_backend_notify_reason_t){ .bf = {
							 b1.bf[0] & b2.bf[0],
						 } };
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_inverse(virtio_backend_notify_reason_t b)
{
	return (virtio_backend_notify_reason_t){ .bf = {
							 (uint64_t)~b.bf[0],
						 } };
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_difference(virtio_backend_notify_reason_t b1,
					virtio_backend_notify_reason_t b2)
{
	virtio_backend_notify_reason_t not_b2 =
		virtio_backend_notify_reason_inverse(b2);
	return virtio_backend_notify_reason_intersection(b1, not_b2);
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_union(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_notify_reason_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_notify_reason_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_notify_reason_t new_value;

	do {
		new_value = virtio_backend_notify_reason_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_intersection(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	virtio_backend_notify_reason_t not_b2 =
		virtio_backend_notify_reason_inverse(b2);
	return virtio_backend_notify_reason_atomic_difference(b1, not_b2,
							      order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_notify_reason_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_notify_reason_t new_value;

	do {
		new_value = virtio_backend_notify_reason_intersection(old_value,
								      b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_notify_reason_t
virtio_backend_notify_reason_atomic_difference(
	_Atomic virtio_backend_notify_reason_t *b1,
	virtio_backend_notify_reason_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_notify_reason_cast(ret_u);

#else
	virtio_backend_notify_reason_t not_b2 =
		virtio_backend_notify_reason_inverse(b2);
	return virtio_backend_notify_reason_atomic_intersection(b1, not_b2,
								order);
#endif
}

void
virtio_backend_notify_reason_set_new_buffer(
	virtio_backend_notify_reason_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
virtio_backend_notify_reason_get_new_buffer(
	const virtio_backend_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_reason_copy_new_buffer(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
virtio_backend_notify_reason_set_reset_request(
	virtio_backend_notify_reason_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
virtio_backend_notify_reason_get_reset_request(
	const virtio_backend_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_reason_copy_reset_request(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

bool
virtio_backend_notify_reason_get_res0_2(
	const virtio_backend_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_reason_set_driver_ok(
	virtio_backend_notify_reason_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
virtio_backend_notify_reason_get_driver_ok(
	const virtio_backend_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_reason_copy_driver_ok(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
virtio_backend_notify_reason_set_failed(
	virtio_backend_notify_reason_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffefU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 4U;
}

bool
virtio_backend_notify_reason_get_failed(
	const virtio_backend_notify_reason_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 4U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_notify_reason_copy_failed(
	virtio_backend_notify_reason_t	     *bit_field_dst,
	const virtio_backend_notify_reason_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x10U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x10U;
}

void
virtio_backend_option_flags_init(virtio_backend_option_flags_t *bit_field)
{
	*bit_field = virtio_backend_option_flags_default();
}

uint64_t
virtio_backend_option_flags_raw(virtio_backend_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

virtio_backend_option_flags_t
virtio_backend_option_flags_clean(virtio_backend_option_flags_t bit_field)
{
	return (virtio_backend_option_flags_t){ .bf = {
							(bit_field.bf[0] &
							 0x4fU),
						} };
}

bool
virtio_backend_option_flags_is_equal(virtio_backend_option_flags_t b1,
				     virtio_backend_option_flags_t b2)
{
	return ((b1.bf[0] & 0x4fU) == (b2.bf[0] & 0x4fU));
}

bool
virtio_backend_option_flags_is_empty(virtio_backend_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x4fU) == 0U);
}

bool
virtio_backend_option_flags_is_clean(virtio_backend_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xffffffffffffffb0U) == 0x0U);
}

virtio_backend_option_flags_t
virtio_backend_option_flags_union(virtio_backend_option_flags_t b1,
				  virtio_backend_option_flags_t b2)
{
	return (virtio_backend_option_flags_t){ .bf = {
							b1.bf[0] | b2.bf[0],
						} };
}

virtio_backend_option_flags_t
virtio_backend_option_flags_intersection(virtio_backend_option_flags_t b1,
					 virtio_backend_option_flags_t b2)
{
	return (virtio_backend_option_flags_t){ .bf = {
							b1.bf[0] & b2.bf[0],
						} };
}

virtio_backend_option_flags_t
virtio_backend_option_flags_inverse(virtio_backend_option_flags_t b)
{
	return (virtio_backend_option_flags_t){ .bf = {
							(uint64_t)~b.bf[0],
						} };
}

virtio_backend_option_flags_t
virtio_backend_option_flags_difference(virtio_backend_option_flags_t b1,
				       virtio_backend_option_flags_t b2)
{
	virtio_backend_option_flags_t not_b2 =
		virtio_backend_option_flags_inverse(b2);
	return virtio_backend_option_flags_intersection(b1, not_b2);
}

virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_union(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_option_flags_t new_value;

	do {
		new_value = virtio_backend_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_intersection(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	virtio_backend_option_flags_t not_b2 =
		virtio_backend_option_flags_inverse(b2);
	return virtio_backend_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_backend_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	virtio_backend_option_flags_t new_value;

	do {
		new_value =
			virtio_backend_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_backend_option_flags_t
virtio_backend_option_flags_atomic_difference(
	_Atomic virtio_backend_option_flags_t *b1,
	virtio_backend_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_backend_option_flags_cast(ret_u);

#else
	virtio_backend_option_flags_t not_b2 =
		virtio_backend_option_flags_inverse(b2);
	return virtio_backend_option_flags_atomic_intersection(b1, not_b2,
							       order);
#endif
}

void
virtio_backend_option_flags_set_sync_reset(
	virtio_backend_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
virtio_backend_option_flags_get_sync_reset(
	const virtio_backend_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_option_flags_copy_sync_reset(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
virtio_backend_option_flags_set_per_queue_irqs(
	virtio_backend_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
virtio_backend_option_flags_get_per_queue_irqs(
	const virtio_backend_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_option_flags_copy_per_queue_irqs(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
virtio_backend_option_flags_set_ignore_config_writes(
	virtio_backend_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffbU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 2U;
}

bool
virtio_backend_option_flags_get_ignore_config_writes(
	const virtio_backend_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_option_flags_copy_ignore_config_writes(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x4U;
}

void
virtio_backend_option_flags_set_valid_me_layout(
	virtio_backend_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffff7U;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 3U;
}

bool
virtio_backend_option_flags_get_valid_me_layout(
	const virtio_backend_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_option_flags_copy_valid_me_layout(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x8U;
}

void
virtio_backend_option_flags_set_valid_type(
	virtio_backend_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffbfU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 6U;
}

bool
virtio_backend_option_flags_get_valid_type(
	const virtio_backend_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_backend_option_flags_copy_valid_type(
	virtio_backend_option_flags_t	    *bit_field_dst,
	const virtio_backend_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x40U;
}

void
virtio_interrupt_init(virtio_interrupt_t *bit_field)
{
	*bit_field = virtio_interrupt_default();
}

uint8_t
virtio_interrupt_raw(virtio_interrupt_t bit_field)
{
	return bit_field.bf[0];
}

virtio_interrupt_t
virtio_interrupt_clean(virtio_interrupt_t bit_field)
{
	return (virtio_interrupt_t){ .bf = {
					     (bit_field.bf[0] & 0x3U),
				     } };
}

bool
virtio_interrupt_is_equal(virtio_interrupt_t b1, virtio_interrupt_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
virtio_interrupt_is_empty(virtio_interrupt_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
virtio_interrupt_is_clean(virtio_interrupt_t bit_field)
{
	return ((bit_field.bf[0] & 0xfcU) == 0x0U);
}

virtio_interrupt_t
virtio_interrupt_union(virtio_interrupt_t b1, virtio_interrupt_t b2)
{
	return (virtio_interrupt_t){ .bf = {
					     b1.bf[0] | b2.bf[0],
				     } };
}

virtio_interrupt_t
virtio_interrupt_intersection(virtio_interrupt_t b1, virtio_interrupt_t b2)
{
	return (virtio_interrupt_t){ .bf = {
					     b1.bf[0] & b2.bf[0],
				     } };
}

virtio_interrupt_t
virtio_interrupt_inverse(virtio_interrupt_t b)
{
	return (virtio_interrupt_t){ .bf = {
					     (uint8_t)~b.bf[0],
				     } };
}

virtio_interrupt_t
virtio_interrupt_difference(virtio_interrupt_t b1, virtio_interrupt_t b2)
{
	virtio_interrupt_t not_b2 = virtio_interrupt_inverse(b2);
	return virtio_interrupt_intersection(b1, not_b2);
}

virtio_interrupt_t
virtio_interrupt_atomic_union(_Atomic virtio_interrupt_t *b1,
			      virtio_interrupt_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint8_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 8-bit atomic load and set, relaxed order
		__asm__ volatile("ldsetb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 8-bit atomic load and set, acquire order
		__asm__ volatile("ldsetab %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 8-bit atomic load and set, release order
		__asm__ volatile("ldsetlb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 8-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetalb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_interrupt_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_interrupt_t old_value = atomic_load_explicit(b1, load_order);
	virtio_interrupt_t new_value;

	do {
		new_value = virtio_interrupt_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_interrupt_t
virtio_interrupt_atomic_intersection(_Atomic virtio_interrupt_t *b1,
				     virtio_interrupt_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	virtio_interrupt_t not_b2 = virtio_interrupt_inverse(b2);
	return virtio_interrupt_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_interrupt_t old_value = atomic_load_explicit(b1, load_order);
	virtio_interrupt_t new_value;

	do {
		new_value = virtio_interrupt_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_interrupt_t
virtio_interrupt_atomic_difference(_Atomic virtio_interrupt_t *b1,
				   virtio_interrupt_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint8_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 8-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclrb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 8-bit atomic load and clr, acquire order
		__asm__ volatile("ldclrab %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 8-bit atomic load and clr, release order
		__asm__ volatile("ldclrlb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 8-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclralb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_interrupt_cast(ret_u);

#else
	virtio_interrupt_t not_b2 = virtio_interrupt_inverse(b2);
	return virtio_interrupt_atomic_intersection(b1, not_b2, order);
#endif
}

void
virtio_interrupt_set_queue_ready(virtio_interrupt_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xfeU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 0U;
}

bool
virtio_interrupt_get_queue_ready(const virtio_interrupt_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_interrupt_copy_queue_ready(virtio_interrupt_t	   *bit_field_dst,
				  const virtio_interrupt_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x1U;
}

void
virtio_interrupt_set_config_update(virtio_interrupt_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xfdU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 1U;
}

bool
virtio_interrupt_get_config_update(const virtio_interrupt_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_interrupt_copy_config_update(virtio_interrupt_t	     *bit_field_dst,
				    const virtio_interrupt_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x2U;
}

void
virtio_iommu_options_init(virtio_iommu_options_t *bit_field)
{
	*bit_field = virtio_iommu_options_default();
}

uint64_t
virtio_iommu_options_raw(virtio_iommu_options_t bit_field)
{
	return bit_field.bf[0];
}

virtio_iommu_options_t
virtio_iommu_options_clean(virtio_iommu_options_t bit_field)
{
	return (virtio_iommu_options_t){ .bf = {
						 // (0x100000000U &
						 // ~0x1ffffffffU) |
						 (uint64_t)(0x0U) |
							 (bit_field.bf[0] &
							  0x1ffffffffU),
					 } };
}

bool
virtio_iommu_options_is_equal(virtio_iommu_options_t b1,
			      virtio_iommu_options_t b2)
{
	return ((b1.bf[0] & 0x1ffffffffU) == (b2.bf[0] & 0x1ffffffffU));
}

bool
virtio_iommu_options_is_clean(virtio_iommu_options_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffe00000000U) == 0x0U);
}

void
virtio_iommu_options_set_max_streams(virtio_iommu_options_t *bit_field,
				     count_t		     val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffff00000000U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0xffffffffU) << 0U;
}

count_t
virtio_iommu_options_get_max_streams(const virtio_iommu_options_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0xffffffffU) << 0U;
	return (count_t)val;
}

void
virtio_iommu_options_copy_max_streams(
	virtio_iommu_options_t	     *bit_field_dst,
	const virtio_iommu_options_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xffffffffU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xffffffffU;
}

bool
virtio_iommu_options_get_addrspace_valid(const virtio_iommu_options_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 32U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
virtio_status_init(virtio_status_t *bit_field)
{
	*bit_field = virtio_status_default();
}

uint8_t
virtio_status_raw(virtio_status_t bit_field)
{
	return bit_field.bf[0];
}

virtio_status_t
virtio_status_clean(virtio_status_t bit_field)
{
	return (virtio_status_t){ .bf = {
					  // (0x40U & ~0xcfU) |
					  (uint8_t)(0x0U) |
						  (bit_field.bf[0] & 0xcfU),
				  } };
}

bool
virtio_status_is_equal(virtio_status_t b1, virtio_status_t b2)
{
	return ((b1.bf[0] & 0xcfU) == (b2.bf[0] & 0xcfU));
}

bool
virtio_status_is_empty(virtio_status_t bit_field)
{
	return ((bit_field.bf[0] & 0xcfU) == 0U);
}

bool
virtio_status_is_clean(virtio_status_t bit_field)
{
	return ((bit_field.bf[0] & 0x30U) == 0x0U);
}

virtio_status_t
virtio_status_union(virtio_status_t b1, virtio_status_t b2)
{
	return (virtio_status_t){ .bf = {
					  b1.bf[0] | b2.bf[0],
				  } };
}

virtio_status_t
virtio_status_intersection(virtio_status_t b1, virtio_status_t b2)
{
	return (virtio_status_t){ .bf = {
					  b1.bf[0] & b2.bf[0],
				  } };
}

virtio_status_t
virtio_status_inverse(virtio_status_t b)
{
	return (virtio_status_t){ .bf = {
					  (uint8_t)~b.bf[0],
				  } };
}

virtio_status_t
virtio_status_difference(virtio_status_t b1, virtio_status_t b2)
{
	virtio_status_t not_b2 = virtio_status_inverse(b2);
	return virtio_status_intersection(b1, not_b2);
}

virtio_status_t
virtio_status_atomic_union(_Atomic virtio_status_t *b1, virtio_status_t b2,
			   memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint8_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 8-bit atomic load and set, relaxed order
		__asm__ volatile("ldsetb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 8-bit atomic load and set, acquire order
		__asm__ volatile("ldsetab %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 8-bit atomic load and set, release order
		__asm__ volatile("ldsetlb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 8-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetalb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_status_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_status_t old_value = atomic_load_explicit(b1, load_order);
	virtio_status_t new_value;

	do {
		new_value = virtio_status_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_status_t
virtio_status_atomic_intersection(_Atomic virtio_status_t *b1,
				  virtio_status_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	virtio_status_t not_b2 = virtio_status_inverse(b2);
	return virtio_status_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	virtio_status_t old_value = atomic_load_explicit(b1, load_order);
	virtio_status_t new_value;

	do {
		new_value = virtio_status_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

virtio_status_t
virtio_status_atomic_difference(_Atomic virtio_status_t *b1, virtio_status_t b2,
				memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint8_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 8-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclrb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 8-bit atomic load and clr, acquire order
		__asm__ volatile("ldclrab %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 8-bit atomic load and clr, release order
		__asm__ volatile("ldclrlb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 8-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclralb %w2, %w0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return virtio_status_cast(ret_u);

#else
	virtio_status_t not_b2 = virtio_status_inverse(b2);
	return virtio_status_atomic_intersection(b1, not_b2, order);
#endif
}

void
virtio_status_set_acknowledge(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xfeU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 0U;
}

bool
virtio_status_get_acknowledge(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_acknowledge(virtio_status_t	     *bit_field_dst,
			       const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x1U;
}

void
virtio_status_set_driver(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xfdU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 1U;
}

bool
virtio_status_get_driver(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_driver(virtio_status_t	*bit_field_dst,
			  const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x2U;
}

void
virtio_status_set_driver_ok(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xfbU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 2U;
}

bool
virtio_status_get_driver_ok(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 2U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_driver_ok(virtio_status_t	   *bit_field_dst,
			     const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x4U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x4U;
}

void
virtio_status_set_features_ok(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xf7U;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 3U;
}

bool
virtio_status_get_features_ok(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 3U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_features_ok(virtio_status_t	     *bit_field_dst,
			       const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x8U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x8U;
}

void
virtio_status_set_device_needs_reset(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0xbfU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 6U;
}

bool
virtio_status_get_device_needs_reset(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_device_needs_reset(virtio_status_t	    *bit_field_dst,
				      const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x40U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x40U;
}

void
virtio_status_set_failed(virtio_status_t *bit_field, bool val)
{
	uint8_t	 bool_val = val ? (uint8_t)1 : (uint8_t)0;
	uint8_t *bf	  = &bit_field->bf[0];
	bf[0] &= (uint8_t)0x7fU;
	bf[0] |= ((bool_val >> 0U) & (uint8_t)0x1U) << 7U;
}

bool
virtio_status_get_failed(const virtio_status_t *bit_field)
{
	uint8_t	       val = 0;
	const uint8_t *bf  = (const uint8_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 7U) & (uint8_t)0x1U) << 0U;
	return val != (uint8_t)0;
}

void
virtio_status_copy_failed(virtio_status_t	*bit_field_dst,
			  const virtio_status_t *bit_field_src)
{
	uint8_t	      *bf_dst = (uint8_t *)&bit_field_dst->bf[0];
	const uint8_t *bf_src = (const uint8_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint8_t)0x80U;
	bf_dst[0] |= bf_src[0] & (uint8_t)0x80U;
}

void
vpci_aperture_init(vpci_aperture_t *bit_field)
{
	*bit_field = vpci_aperture_default();
}

uint64_t
vpci_aperture_raw(vpci_aperture_t bit_field)
{
	return bit_field.bf[0];
}

vpci_aperture_t
vpci_aperture_clean(vpci_aperture_t bit_field)
{
	return (vpci_aperture_t){ .bf = {
					  (bit_field.bf[0] &
					   0xffffffffffffffffU),
				  } };
}

bool
vpci_aperture_is_equal(vpci_aperture_t b1, vpci_aperture_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
vpci_aperture_is_clean(vpci_aperture_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
vpci_aperture_set_bits(vpci_aperture_t *bit_field, count_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xffffffffffffffc0U;
	bf[0] |= (((uint64_t)val >> 0U) & (uint64_t)0x3fU) << 0U;
}

count_t
vpci_aperture_get_bits(const vpci_aperture_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x3fU) << 0U;
	return (count_t)val;
}

void
vpci_aperture_copy_bits(vpci_aperture_t	      *bit_field_dst,
			const vpci_aperture_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x3fU;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x3fU;
}

uint64_t
vpci_aperture_get_res0(const vpci_aperture_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 6U) & (uint64_t)0x3fU) << 0U;
	return (uint64_t)val;
}

void
vpci_aperture_set_base(vpci_aperture_t *bit_field, vmaddr_t val)
{
	uint64_t *bf = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffU;
	bf[0] |= (((uint64_t)val >> 12U) & (uint64_t)0xfffffffffffffU) << 12U;
}

vmaddr_t
vpci_aperture_get_base(const vpci_aperture_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 12U) & (uint64_t)0xfffffffffffffU) << 12U;
	return (vmaddr_t)val;
}

void
vpci_aperture_copy_base(vpci_aperture_t	      *bit_field_dst,
			const vpci_aperture_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0xfffffffffffff000U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0xfffffffffffff000U;
}

void
vpci_option_flags_init(vpci_option_flags_t *bit_field)
{
	*bit_field = vpci_option_flags_default();
}

uint64_t
vpci_option_flags_raw(vpci_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

vpci_option_flags_t
vpci_option_flags_clean(vpci_option_flags_t bit_field)
{
	return (vpci_option_flags_t){ .bf = {
					      // (0x1U & ~0xffffffffffffffffU) |
					      (uint64_t)(0x0U) |
						      (bit_field.bf[0] &
						       0xffffffffffffffffU),
				      } };
}

bool
vpci_option_flags_is_equal(vpci_option_flags_t b1, vpci_option_flags_t b2)
{
	return ((b1.bf[0] & 0xffffffffffffffffU) ==
		(b2.bf[0] & 0xffffffffffffffffU));
}

bool
vpci_option_flags_is_clean(vpci_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x0U) == 0x0U);
}

void
vpci_option_flags_set_pcie(vpci_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
vpci_option_flags_get_pcie(const vpci_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vpci_option_flags_copy_pcie(vpci_option_flags_t	      *bit_field_dst,
			    const vpci_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

uint64_t
vpci_option_flags_get_res0(const vpci_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x7fffffffffffffffU) << 0U;
	return (uint64_t)val;
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

vpm_group_option_flags_t
vpm_group_option_flags_clean(vpm_group_option_flags_t bit_field)
{
	return (vpm_group_option_flags_t){ .bf = {
						   (bit_field.bf[0] & 0x3U),
					   } };
}

bool
vpm_group_option_flags_is_equal(vpm_group_option_flags_t b1,
				vpm_group_option_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
vpm_group_option_flags_is_empty(vpm_group_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
vpm_group_option_flags_is_clean(vpm_group_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
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
						   (uint64_t)~b.bf[0],
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
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vpm_group_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vpm_group_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vpm_group_option_flags_t new_value;

	do {
		new_value = vpm_group_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vpm_group_option_flags_t
vpm_group_option_flags_atomic_intersection(_Atomic vpm_group_option_flags_t *b1,
					   vpm_group_option_flags_t	     b2,
					   memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	vpm_group_option_flags_t not_b2 = vpm_group_option_flags_inverse(b2);
	return vpm_group_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	vpm_group_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	vpm_group_option_flags_t new_value;

	do {
		new_value = vpm_group_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

vpm_group_option_flags_t
vpm_group_option_flags_atomic_difference(_Atomic vpm_group_option_flags_t *b1,
					 vpm_group_option_flags_t	   b2,
					 memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return vpm_group_option_flags_cast(ret_u);

#else
	vpm_group_option_flags_t not_b2 = vpm_group_option_flags_inverse(b2);
	return vpm_group_option_flags_atomic_intersection(b1, not_b2, order);
#endif
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
vpm_group_option_flags_set_explicit_wakeup(vpm_group_option_flags_t *bit_field,
					   bool			     val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
vpm_group_option_flags_get_explicit_wakeup(
	const vpm_group_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
vpm_group_option_flags_copy_explicit_wakeup(
	vpm_group_option_flags_t       *bit_field_dst,
	const vpm_group_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

void
watchdog_bind_option_flags_init(watchdog_bind_option_flags_t *bit_field)
{
	*bit_field = watchdog_bind_option_flags_default();
}

uint64_t
watchdog_bind_option_flags_raw(watchdog_bind_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_clean(watchdog_bind_option_flags_t bit_field)
{
	return (watchdog_bind_option_flags_t){ .bf = {
						       (bit_field.bf[0] & 0x1U),
					       } };
}

bool
watchdog_bind_option_flags_is_equal(watchdog_bind_option_flags_t b1,
				    watchdog_bind_option_flags_t b2)
{
	return ((b1.bf[0] & 0x1U) == (b2.bf[0] & 0x1U));
}

bool
watchdog_bind_option_flags_is_empty(watchdog_bind_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x1U) == 0U);
}

bool
watchdog_bind_option_flags_is_clean(watchdog_bind_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffeU) == 0x0U);
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_union(watchdog_bind_option_flags_t b1,
				 watchdog_bind_option_flags_t b2)
{
	return (watchdog_bind_option_flags_t){ .bf = {
						       b1.bf[0] | b2.bf[0],
					       } };
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_intersection(watchdog_bind_option_flags_t b1,
					watchdog_bind_option_flags_t b2)
{
	return (watchdog_bind_option_flags_t){ .bf = {
						       b1.bf[0] & b2.bf[0],
					       } };
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_inverse(watchdog_bind_option_flags_t b)
{
	return (watchdog_bind_option_flags_t){ .bf = {
						       (uint64_t)~b.bf[0],
					       } };
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_difference(watchdog_bind_option_flags_t b1,
				      watchdog_bind_option_flags_t b2)
{
	watchdog_bind_option_flags_t not_b2 =
		watchdog_bind_option_flags_inverse(b2);
	return watchdog_bind_option_flags_intersection(b1, not_b2);
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_union(_Atomic watchdog_bind_option_flags_t *b1,
					watchdog_bind_option_flags_t b2,
					memory_order		     order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return watchdog_bind_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	watchdog_bind_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	watchdog_bind_option_flags_t new_value;

	do {
		new_value = watchdog_bind_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_intersection(
	_Atomic watchdog_bind_option_flags_t *b1,
	watchdog_bind_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	watchdog_bind_option_flags_t not_b2 =
		watchdog_bind_option_flags_inverse(b2);
	return watchdog_bind_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	watchdog_bind_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	watchdog_bind_option_flags_t new_value;

	do {
		new_value =
			watchdog_bind_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

watchdog_bind_option_flags_t
watchdog_bind_option_flags_atomic_difference(
	_Atomic watchdog_bind_option_flags_t *b1,
	watchdog_bind_option_flags_t b2, memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return watchdog_bind_option_flags_cast(ret_u);

#else
	watchdog_bind_option_flags_t not_b2 =
		watchdog_bind_option_flags_inverse(b2);
	return watchdog_bind_option_flags_atomic_intersection(b1, not_b2,
							      order);
#endif
}

void
watchdog_bind_option_flags_set_bite_virq(
	watchdog_bind_option_flags_t *bit_field, bool val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
watchdog_bind_option_flags_get_bite_virq(
	const watchdog_bind_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
watchdog_bind_option_flags_copy_bite_virq(
	watchdog_bind_option_flags_t	   *bit_field_dst,
	const watchdog_bind_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
watchdog_option_flags_init(watchdog_option_flags_t *bit_field)
{
	*bit_field = watchdog_option_flags_default();
}

uint64_t
watchdog_option_flags_raw(watchdog_option_flags_t bit_field)
{
	return bit_field.bf[0];
}

watchdog_option_flags_t
watchdog_option_flags_clean(watchdog_option_flags_t bit_field)
{
	return (watchdog_option_flags_t){ .bf = {
						  (bit_field.bf[0] & 0x3U),
					  } };
}

bool
watchdog_option_flags_is_equal(watchdog_option_flags_t b1,
			       watchdog_option_flags_t b2)
{
	return ((b1.bf[0] & 0x3U) == (b2.bf[0] & 0x3U));
}

bool
watchdog_option_flags_is_empty(watchdog_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0x3U) == 0U);
}

bool
watchdog_option_flags_is_clean(watchdog_option_flags_t bit_field)
{
	return ((bit_field.bf[0] & 0xfffffffffffffffcU) == 0x0U);
}

watchdog_option_flags_t
watchdog_option_flags_union(watchdog_option_flags_t b1,
			    watchdog_option_flags_t b2)
{
	return (watchdog_option_flags_t){ .bf = {
						  b1.bf[0] | b2.bf[0],
					  } };
}

watchdog_option_flags_t
watchdog_option_flags_intersection(watchdog_option_flags_t b1,
				   watchdog_option_flags_t b2)
{
	return (watchdog_option_flags_t){ .bf = {
						  b1.bf[0] & b2.bf[0],
					  } };
}

watchdog_option_flags_t
watchdog_option_flags_inverse(watchdog_option_flags_t b)
{
	return (watchdog_option_flags_t){ .bf = {
						  (uint64_t)~b.bf[0],
					  } };
}

watchdog_option_flags_t
watchdog_option_flags_difference(watchdog_option_flags_t b1,
				 watchdog_option_flags_t b2)
{
	watchdog_option_flags_t not_b2 = watchdog_option_flags_inverse(b2);
	return watchdog_option_flags_intersection(b1, not_b2);
}

watchdog_option_flags_t
watchdog_option_flags_atomic_union(_Atomic watchdog_option_flags_t *b1,
				   watchdog_option_flags_t	    b2,
				   memory_order			    order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and set, relaxed order
		__asm__ volatile("ldset %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and set, acquire order
		__asm__ volatile("ldseta %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and set, release order
		__asm__ volatile("ldsetl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and set, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldsetal %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return watchdog_option_flags_cast(ret_u);

#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	watchdog_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	watchdog_option_flags_t new_value;

	do {
		new_value = watchdog_option_flags_union(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

watchdog_option_flags_t
watchdog_option_flags_atomic_intersection(_Atomic watchdog_option_flags_t *b1,
					  watchdog_option_flags_t	   b2,
					  memory_order order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	watchdog_option_flags_t not_b2 = watchdog_option_flags_inverse(b2);
	return watchdog_option_flags_atomic_difference(b1, not_b2, order);
#else
	memory_order load_order =
		(order == memory_order_acq_rel)	  ? memory_order_acquire
		: (order == memory_order_release) ? memory_order_relaxed
						  : order;

	watchdog_option_flags_t old_value =
		atomic_load_explicit(b1, load_order);
	watchdog_option_flags_t new_value;

	do {
		new_value = watchdog_option_flags_intersection(old_value, b2);
	} while (!atomic_compare_exchange_weak_explicit(
		b1, &old_value, new_value, order, load_order));

	return old_value;
#endif
}

watchdog_option_flags_t
watchdog_option_flags_atomic_difference(_Atomic watchdog_option_flags_t *b1,
					watchdog_option_flags_t		 b2,
					memory_order			 order)
{
#if defined(__aarch64__) && defined(__ARM_FEATURE_ATOMICS)
	uint64_t ret_u;
	switch (order) {
	case memory_order_relaxed:
		// 64-bit atomic load and clr, relaxed order
		__asm__ volatile("ldclr %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acquire:
	case memory_order_consume:
		// 64-bit atomic load and clr, acquire order
		__asm__ volatile("ldclra %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		// Compiler acquire fence to prevent later stores migrating
		// before the above atomic load
		atomic_signal_fence(memory_order_acquire);
		break;
	case memory_order_release:
		// Compiler release fence to prevent earlier accesses migrating
		// after the below atomic load
		atomic_signal_fence(memory_order_release);
		// 64-bit atomic load and clr, release order
		__asm__ volatile("ldclrl %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0]));
		break;
	case memory_order_acq_rel:
	case memory_order_seq_cst:
	default:
		// 64-bit atomic load and clr, acquire and release
		// order, with a full compiler barrier
		__asm__ volatile("ldclral %2, %0, %1"
				 : "=r"(ret_u), "+Q"(*b1)
				 : "r"(b2.bf[0])
				 : "memory");
		break;
	}
	return watchdog_option_flags_cast(ret_u);

#else
	watchdog_option_flags_t not_b2 = watchdog_option_flags_inverse(b2);
	return watchdog_option_flags_atomic_intersection(b1, not_b2, order);
#endif
}

void
watchdog_option_flags_set_critical_bite(watchdog_option_flags_t *bit_field,
					bool			 val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffeU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 0U;
}

bool
watchdog_option_flags_get_critical_bite(const watchdog_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 0U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
watchdog_option_flags_copy_critical_bite(
	watchdog_option_flags_t	      *bit_field_dst,
	const watchdog_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x1U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x1U;
}

void
watchdog_option_flags_set_fatal_bite(watchdog_option_flags_t *bit_field,
				     bool		      val)
{
	uint64_t  bool_val = val ? (uint64_t)1 : (uint64_t)0;
	uint64_t *bf	   = &bit_field->bf[0];
	bf[0] &= (uint64_t)0xfffffffffffffffdU;
	bf[0] |= ((bool_val >> 0U) & (uint64_t)0x1U) << 1U;
}

bool
watchdog_option_flags_get_fatal_bite(const watchdog_option_flags_t *bit_field)
{
	uint64_t	val = 0;
	const uint64_t *bf  = (const uint64_t *)&bit_field->bf[0];

	val |= ((bf[0] >> 1U) & (uint64_t)0x1U) << 0U;
	return val != (uint64_t)0;
}

void
watchdog_option_flags_copy_fatal_bite(
	watchdog_option_flags_t	      *bit_field_dst,
	const watchdog_option_flags_t *bit_field_src)
{
	uint64_t       *bf_dst = (uint64_t *)&bit_field_dst->bf[0];
	const uint64_t *bf_src = (const uint64_t *)&bit_field_src->bf[0];
	bf_dst[0] &= ~(uint64_t)0x2U;
	bf_dst[0] |= bf_src[0] & (uint64_t)0x2U;
}

// Enumeration accessors

addrspace_access_type_t
addrspace_access_type_raw_cast(uint32_t val)
{
	addrspace_access_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_READ:
		ret = ADDRSPACE_ACCESS_TYPE_READ;
		break;
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_WRITE:
		ret = ADDRSPACE_ACCESS_TYPE_WRITE;
		break;
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_EXECUTE:
		ret = ADDRSPACE_ACCESS_TYPE_EXECUTE;
		break;
	default:
		// Invalid addrspace_access_type
		__builtin_trap();
	}
#else
	ret = (addrspace_access_type_t)val;
#endif

	return ret;
}

addrspace_access_type_result_t
addrspace_access_type_raw_cast_safe(uint32_t val)
{
	addrspace_access_type_result_t ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_READ:
		ret = addrspace_access_type_result_ok(
			ADDRSPACE_ACCESS_TYPE_READ);
		break;
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_WRITE:
		ret = addrspace_access_type_result_ok(
			ADDRSPACE_ACCESS_TYPE_WRITE);
		break;
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_EXECUTE:
		ret = addrspace_access_type_result_ok(
			ADDRSPACE_ACCESS_TYPE_EXECUTE);
		break;
	default:
		ret = addrspace_access_type_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
addrspace_access_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_READ:
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_WRITE:
	case (uint32_t)ADDRSPACE_ACCESS_TYPE_EXECUTE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

addrspace_info_area_id_owner_t
addrspace_info_area_id_owner_raw_cast(uint32_t val)
{
	addrspace_info_area_id_owner_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_INVALID:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_INVALID;
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH;
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM;
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_RM:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_RM;
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_QCRM:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_QCRM;
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_DEV:
		ret = ADDRSPACE_INFO_AREA_ID_OWNER_DEV;
		break;
	default:
		// Invalid addrspace_info_area_id_owner
		__builtin_trap();
	}
#else
	ret = (addrspace_info_area_id_owner_t)val;
#endif

	return ret;
}

addrspace_info_area_id_owner_result_t
addrspace_info_area_id_owner_raw_cast_safe(uint32_t val)
{
	addrspace_info_area_id_owner_result_t ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_INVALID:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_INVALID);
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH);
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM);
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_RM:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_RM);
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_QCRM:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_QCRM);
		break;
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_DEV:
		ret = addrspace_info_area_id_owner_result_ok(
			ADDRSPACE_INFO_AREA_ID_OWNER_DEV);
		break;
	default:
		ret = addrspace_info_area_id_owner_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
addrspace_info_area_id_owner_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_INVALID:
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_GUNYAH:
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_ROOTVM:
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_RM:
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_QCRM:
	case (uint32_t)ADDRSPACE_INFO_AREA_ID_OWNER_DEV:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

addrspace_range_configure_op_t
addrspace_range_configure_op_raw_cast(uint32_t val)
{
	addrspace_range_configure_op_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO:
		ret = ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO;
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO:
		ret = ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO;
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE:
		ret = ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE;
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE:
		ret = ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE;
		break;
	default:
		// Invalid addrspace_range_configure_op
		__builtin_trap();
	}
#else
	ret = (addrspace_range_configure_op_t)val;
#endif

	return ret;
}

addrspace_range_configure_op_result_t
addrspace_range_configure_op_raw_cast_safe(uint32_t val)
{
	addrspace_range_configure_op_result_t ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO:
		ret = addrspace_range_configure_op_result_ok(
			ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO);
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO:
		ret = addrspace_range_configure_op_result_ok(
			ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO);
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE:
		ret = addrspace_range_configure_op_result_ok(
			ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE);
		break;
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE:
		ret = addrspace_range_configure_op_result_ok(
			ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE);
		break;
	default:
		ret = addrspace_range_configure_op_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
addrspace_range_configure_op_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_VMMIO:
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_VMMIO:
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_ADD_PRIVATE:
	case (uint32_t)ADDRSPACE_RANGE_CONFIGURE_OP_REMOVE_PRIVATE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

addrspace_resume_action_t
addrspace_resume_action_raw_cast(uint32_t val)
{
	addrspace_resume_action_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)ADDRSPACE_RESUME_ACTION_DEFAULT:
		ret = ADDRSPACE_RESUME_ACTION_DEFAULT;
		break;
	case (uint32_t)ADDRSPACE_RESUME_ACTION_RETRY:
		ret = ADDRSPACE_RESUME_ACTION_RETRY;
		break;
	case (uint32_t)ADDRSPACE_RESUME_ACTION_FAULT:
		ret = ADDRSPACE_RESUME_ACTION_FAULT;
		break;
	default:
		// Invalid addrspace_resume_action
		__builtin_trap();
	}
#else
	ret = (addrspace_resume_action_t)val;
#endif

	return ret;
}

addrspace_resume_action_result_t
addrspace_resume_action_raw_cast_safe(uint32_t val)
{
	addrspace_resume_action_result_t ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_RESUME_ACTION_DEFAULT:
		ret = addrspace_resume_action_result_ok(
			ADDRSPACE_RESUME_ACTION_DEFAULT);
		break;
	case (uint32_t)ADDRSPACE_RESUME_ACTION_RETRY:
		ret = addrspace_resume_action_result_ok(
			ADDRSPACE_RESUME_ACTION_RETRY);
		break;
	case (uint32_t)ADDRSPACE_RESUME_ACTION_FAULT:
		ret = addrspace_resume_action_result_ok(
			ADDRSPACE_RESUME_ACTION_FAULT);
		break;
	default:
		ret = addrspace_resume_action_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
addrspace_resume_action_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)ADDRSPACE_RESUME_ACTION_DEFAULT:
	case (uint32_t)ADDRSPACE_RESUME_ACTION_RETRY:
	case (uint32_t)ADDRSPACE_RESUME_ACTION_FAULT:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

allocator_memtype_t
allocator_memtype_raw_cast(uint32_t val)
{
	allocator_memtype_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)ALLOCATOR_MEMTYPE_HYPERVISOR:
		ret = ALLOCATOR_MEMTYPE_HYPERVISOR;
		break;
	case (uint32_t)ALLOCATOR_MEMTYPE_VM_PAGE_TABLE:
		ret = ALLOCATOR_MEMTYPE_VM_PAGE_TABLE;
		break;
	case (uint32_t)ALLOCATOR_MEMTYPE_TZ_FFI:
		ret = ALLOCATOR_MEMTYPE_TZ_FFI;
		break;
	default:
		// Invalid allocator_memtype
		__builtin_trap();
	}
#else
	ret = (allocator_memtype_t)val;
#endif

	return ret;
}

allocator_memtype_result_t
allocator_memtype_raw_cast_safe(uint32_t val)
{
	allocator_memtype_result_t ret;

	switch (val) {
	case (uint32_t)ALLOCATOR_MEMTYPE_HYPERVISOR:
		ret = allocator_memtype_result_ok(ALLOCATOR_MEMTYPE_HYPERVISOR);
		break;
	case (uint32_t)ALLOCATOR_MEMTYPE_VM_PAGE_TABLE:
		ret = allocator_memtype_result_ok(
			ALLOCATOR_MEMTYPE_VM_PAGE_TABLE);
		break;
	case (uint32_t)ALLOCATOR_MEMTYPE_TZ_FFI:
		ret = allocator_memtype_result_ok(ALLOCATOR_MEMTYPE_TZ_FFI);
		break;
	default:
		ret = allocator_memtype_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
allocator_memtype_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)ALLOCATOR_MEMTYPE_HYPERVISOR:
	case (uint32_t)ALLOCATOR_MEMTYPE_VM_PAGE_TABLE:
	case (uint32_t)ALLOCATOR_MEMTYPE_TZ_FFI:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

error_t
error_raw_cast(int32_t val)
{
	error_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (int32_t)OK:
		ret = OK;
		break;
	case (int32_t)ERROR_UNIMPLEMENTED:
		ret = ERROR_UNIMPLEMENTED;
		break;
	case (int32_t)ERROR_RETRY:
		ret = ERROR_RETRY;
		break;
	case (int32_t)ERROR_ARGUMENT_INVALID:
		ret = ERROR_ARGUMENT_INVALID;
		break;
	case (int32_t)ERROR_ARGUMENT_SIZE:
		ret = ERROR_ARGUMENT_SIZE;
		break;
	case (int32_t)ERROR_ARGUMENT_ALIGNMENT:
		ret = ERROR_ARGUMENT_ALIGNMENT;
		break;
	case (int32_t)ERROR_NOMEM:
		ret = ERROR_NOMEM;
		break;
	case (int32_t)ERROR_NORESOURCES:
		ret = ERROR_NORESOURCES;
		break;
	case (int32_t)ERROR_ADDR_OVERFLOW:
		ret = ERROR_ADDR_OVERFLOW;
		break;
	case (int32_t)ERROR_ADDR_UNDERFLOW:
		ret = ERROR_ADDR_UNDERFLOW;
		break;
	case (int32_t)ERROR_ADDR_INVALID:
		ret = ERROR_ADDR_INVALID;
		break;
	case (int32_t)ERROR_ADDR_OVERLAP:
		ret = ERROR_ADDR_OVERLAP;
		break;
	case (int32_t)ERROR_ADDR_NOTFOUND:
		ret = ERROR_ADDR_NOTFOUND;
		break;
	case (int32_t)ERROR_DENIED:
		ret = ERROR_DENIED;
		break;
	case (int32_t)ERROR_BUSY:
		ret = ERROR_BUSY;
		break;
	case (int32_t)ERROR_IDLE:
		ret = ERROR_IDLE;
		break;
	case (int32_t)ERROR_FAILURE:
		ret = ERROR_FAILURE;
		break;
	case (int32_t)ERROR_ALLOCATOR_RANGE_OVERLAPPING:
		ret = ERROR_ALLOCATOR_RANGE_OVERLAPPING;
		break;
	case (int32_t)ERROR_ALLOCATOR_MEM_INUSE:
		ret = ERROR_ALLOCATOR_MEM_INUSE;
		break;
	case (int32_t)ERROR_STRING_TRUNCATED:
		ret = ERROR_STRING_TRUNCATED;
		break;
	case (int32_t)ERROR_STRING_REACHED_END:
		ret = ERROR_STRING_REACHED_END;
		break;
	case (int32_t)ERROR_STRING_INVALID_FORMAT:
		ret = ERROR_STRING_INVALID_FORMAT;
		break;
	case (int32_t)ERROR_STRING_MISSING_PLACEHOLDER:
		ret = ERROR_STRING_MISSING_PLACEHOLDER;
		break;
	case (int32_t)ERROR_STRING_MISSING_ARGUMENT:
		ret = ERROR_STRING_MISSING_ARGUMENT;
		break;
	case (int32_t)ERROR_MEMDB_EMPTY:
		ret = ERROR_MEMDB_EMPTY;
		break;
	case (int32_t)ERROR_MEMDB_NOT_OWNER:
		ret = ERROR_MEMDB_NOT_OWNER;
		break;
	case (int32_t)ERROR_MEMEXTENT_MAPPINGS_FULL:
		ret = ERROR_MEMEXTENT_MAPPINGS_FULL;
		break;
	case (int32_t)ERROR_MEMEXTENT_TYPE:
		ret = ERROR_MEMEXTENT_TYPE;
		break;
	case (int32_t)ERROR_EXISTING_MAPPING:
		ret = ERROR_EXISTING_MAPPING;
		break;
	case (int32_t)ERROR_VIRQ_BOUND:
		ret = ERROR_VIRQ_BOUND;
		break;
	case (int32_t)ERROR_VIRQ_NOT_BOUND:
		ret = ERROR_VIRQ_NOT_BOUND;
		break;
	case (int32_t)ERROR_MSGQUEUE_EMPTY:
		ret = ERROR_MSGQUEUE_EMPTY;
		break;
	case (int32_t)ERROR_MSGQUEUE_FULL:
		ret = ERROR_MSGQUEUE_FULL;
		break;
	case (int32_t)ERROR_CSPACE_CAP_NULL:
		ret = ERROR_CSPACE_CAP_NULL;
		break;
	case (int32_t)ERROR_CSPACE_CAP_REVOKED:
		ret = ERROR_CSPACE_CAP_REVOKED;
		break;
	case (int32_t)ERROR_CSPACE_WRONG_OBJECT_TYPE:
		ret = ERROR_CSPACE_WRONG_OBJECT_TYPE;
		break;
	case (int32_t)ERROR_CSPACE_INSUFFICIENT_RIGHTS:
		ret = ERROR_CSPACE_INSUFFICIENT_RIGHTS;
		break;
	case (int32_t)ERROR_CSPACE_FULL:
		ret = ERROR_CSPACE_FULL;
		break;
	case (int32_t)ERROR_OBJECT_STATE:
		ret = ERROR_OBJECT_STATE;
		break;
	case (int32_t)ERROR_OBJECT_CONFIG:
		ret = ERROR_OBJECT_CONFIG;
		break;
	case (int32_t)ERROR_OBJECT_CONFIGURED:
		ret = ERROR_OBJECT_CONFIGURED;
		break;
	default:
		// Invalid error
		__builtin_trap();
	}
#else
	ret = (error_t)val;
#endif

	return ret;
}

error_result_t
error_raw_cast_safe(int32_t val)
{
	error_result_t ret;

	switch (val) {
	case (int32_t)OK:
		ret = error_result_ok(OK);
		break;
	case (int32_t)ERROR_UNIMPLEMENTED:
		ret = error_result_ok(ERROR_UNIMPLEMENTED);
		break;
	case (int32_t)ERROR_RETRY:
		ret = error_result_ok(ERROR_RETRY);
		break;
	case (int32_t)ERROR_ARGUMENT_INVALID:
		ret = error_result_ok(ERROR_ARGUMENT_INVALID);
		break;
	case (int32_t)ERROR_ARGUMENT_SIZE:
		ret = error_result_ok(ERROR_ARGUMENT_SIZE);
		break;
	case (int32_t)ERROR_ARGUMENT_ALIGNMENT:
		ret = error_result_ok(ERROR_ARGUMENT_ALIGNMENT);
		break;
	case (int32_t)ERROR_NOMEM:
		ret = error_result_ok(ERROR_NOMEM);
		break;
	case (int32_t)ERROR_NORESOURCES:
		ret = error_result_ok(ERROR_NORESOURCES);
		break;
	case (int32_t)ERROR_ADDR_OVERFLOW:
		ret = error_result_ok(ERROR_ADDR_OVERFLOW);
		break;
	case (int32_t)ERROR_ADDR_UNDERFLOW:
		ret = error_result_ok(ERROR_ADDR_UNDERFLOW);
		break;
	case (int32_t)ERROR_ADDR_INVALID:
		ret = error_result_ok(ERROR_ADDR_INVALID);
		break;
	case (int32_t)ERROR_ADDR_OVERLAP:
		ret = error_result_ok(ERROR_ADDR_OVERLAP);
		break;
	case (int32_t)ERROR_ADDR_NOTFOUND:
		ret = error_result_ok(ERROR_ADDR_NOTFOUND);
		break;
	case (int32_t)ERROR_DENIED:
		ret = error_result_ok(ERROR_DENIED);
		break;
	case (int32_t)ERROR_BUSY:
		ret = error_result_ok(ERROR_BUSY);
		break;
	case (int32_t)ERROR_IDLE:
		ret = error_result_ok(ERROR_IDLE);
		break;
	case (int32_t)ERROR_FAILURE:
		ret = error_result_ok(ERROR_FAILURE);
		break;
	case (int32_t)ERROR_ALLOCATOR_RANGE_OVERLAPPING:
		ret = error_result_ok(ERROR_ALLOCATOR_RANGE_OVERLAPPING);
		break;
	case (int32_t)ERROR_ALLOCATOR_MEM_INUSE:
		ret = error_result_ok(ERROR_ALLOCATOR_MEM_INUSE);
		break;
	case (int32_t)ERROR_STRING_TRUNCATED:
		ret = error_result_ok(ERROR_STRING_TRUNCATED);
		break;
	case (int32_t)ERROR_STRING_REACHED_END:
		ret = error_result_ok(ERROR_STRING_REACHED_END);
		break;
	case (int32_t)ERROR_STRING_INVALID_FORMAT:
		ret = error_result_ok(ERROR_STRING_INVALID_FORMAT);
		break;
	case (int32_t)ERROR_STRING_MISSING_PLACEHOLDER:
		ret = error_result_ok(ERROR_STRING_MISSING_PLACEHOLDER);
		break;
	case (int32_t)ERROR_STRING_MISSING_ARGUMENT:
		ret = error_result_ok(ERROR_STRING_MISSING_ARGUMENT);
		break;
	case (int32_t)ERROR_MEMDB_EMPTY:
		ret = error_result_ok(ERROR_MEMDB_EMPTY);
		break;
	case (int32_t)ERROR_MEMDB_NOT_OWNER:
		ret = error_result_ok(ERROR_MEMDB_NOT_OWNER);
		break;
	case (int32_t)ERROR_MEMEXTENT_MAPPINGS_FULL:
		ret = error_result_ok(ERROR_MEMEXTENT_MAPPINGS_FULL);
		break;
	case (int32_t)ERROR_MEMEXTENT_TYPE:
		ret = error_result_ok(ERROR_MEMEXTENT_TYPE);
		break;
	case (int32_t)ERROR_EXISTING_MAPPING:
		ret = error_result_ok(ERROR_EXISTING_MAPPING);
		break;
	case (int32_t)ERROR_VIRQ_BOUND:
		ret = error_result_ok(ERROR_VIRQ_BOUND);
		break;
	case (int32_t)ERROR_VIRQ_NOT_BOUND:
		ret = error_result_ok(ERROR_VIRQ_NOT_BOUND);
		break;
	case (int32_t)ERROR_MSGQUEUE_EMPTY:
		ret = error_result_ok(ERROR_MSGQUEUE_EMPTY);
		break;
	case (int32_t)ERROR_MSGQUEUE_FULL:
		ret = error_result_ok(ERROR_MSGQUEUE_FULL);
		break;
	case (int32_t)ERROR_CSPACE_CAP_NULL:
		ret = error_result_ok(ERROR_CSPACE_CAP_NULL);
		break;
	case (int32_t)ERROR_CSPACE_CAP_REVOKED:
		ret = error_result_ok(ERROR_CSPACE_CAP_REVOKED);
		break;
	case (int32_t)ERROR_CSPACE_WRONG_OBJECT_TYPE:
		ret = error_result_ok(ERROR_CSPACE_WRONG_OBJECT_TYPE);
		break;
	case (int32_t)ERROR_CSPACE_INSUFFICIENT_RIGHTS:
		ret = error_result_ok(ERROR_CSPACE_INSUFFICIENT_RIGHTS);
		break;
	case (int32_t)ERROR_CSPACE_FULL:
		ret = error_result_ok(ERROR_CSPACE_FULL);
		break;
	case (int32_t)ERROR_OBJECT_STATE:
		ret = error_result_ok(ERROR_OBJECT_STATE);
		break;
	case (int32_t)ERROR_OBJECT_CONFIG:
		ret = error_result_ok(ERROR_OBJECT_CONFIG);
		break;
	case (int32_t)ERROR_OBJECT_CONFIGURED:
		ret = error_result_ok(ERROR_OBJECT_CONFIGURED);
		break;
	default:
		ret = error_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
error_raw_is_valid(int32_t val)
{
	bool ret;

	switch (val) {
	case (int32_t)OK:
	case (int32_t)ERROR_UNIMPLEMENTED:
	case (int32_t)ERROR_RETRY:
	case (int32_t)ERROR_ARGUMENT_INVALID:
	case (int32_t)ERROR_ARGUMENT_SIZE:
	case (int32_t)ERROR_ARGUMENT_ALIGNMENT:
	case (int32_t)ERROR_NOMEM:
	case (int32_t)ERROR_NORESOURCES:
	case (int32_t)ERROR_ADDR_OVERFLOW:
	case (int32_t)ERROR_ADDR_UNDERFLOW:
	case (int32_t)ERROR_ADDR_INVALID:
	case (int32_t)ERROR_ADDR_OVERLAP:
	case (int32_t)ERROR_ADDR_NOTFOUND:
	case (int32_t)ERROR_DENIED:
	case (int32_t)ERROR_BUSY:
	case (int32_t)ERROR_IDLE:
	case (int32_t)ERROR_FAILURE:
	case (int32_t)ERROR_ALLOCATOR_RANGE_OVERLAPPING:
	case (int32_t)ERROR_ALLOCATOR_MEM_INUSE:
	case (int32_t)ERROR_STRING_TRUNCATED:
	case (int32_t)ERROR_STRING_REACHED_END:
	case (int32_t)ERROR_STRING_INVALID_FORMAT:
	case (int32_t)ERROR_STRING_MISSING_PLACEHOLDER:
	case (int32_t)ERROR_STRING_MISSING_ARGUMENT:
	case (int32_t)ERROR_MEMDB_EMPTY:
	case (int32_t)ERROR_MEMDB_NOT_OWNER:
	case (int32_t)ERROR_MEMEXTENT_MAPPINGS_FULL:
	case (int32_t)ERROR_MEMEXTENT_TYPE:
	case (int32_t)ERROR_EXISTING_MAPPING:
	case (int32_t)ERROR_VIRQ_BOUND:
	case (int32_t)ERROR_VIRQ_NOT_BOUND:
	case (int32_t)ERROR_MSGQUEUE_EMPTY:
	case (int32_t)ERROR_MSGQUEUE_FULL:
	case (int32_t)ERROR_CSPACE_CAP_NULL:
	case (int32_t)ERROR_CSPACE_CAP_REVOKED:
	case (int32_t)ERROR_CSPACE_WRONG_OBJECT_TYPE:
	case (int32_t)ERROR_CSPACE_INSUFFICIENT_RIGHTS:
	case (int32_t)ERROR_CSPACE_FULL:
	case (int32_t)ERROR_OBJECT_STATE:
	case (int32_t)ERROR_OBJECT_CONFIG:
	case (int32_t)ERROR_OBJECT_CONFIGURED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

hyp_variant_t
hyp_variant_raw_cast(uint32_t val)
{
	hyp_variant_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)HYP_VARIANT_UNKNOWN:
		ret = HYP_VARIANT_UNKNOWN;
		break;
	case (uint32_t)HYP_VARIANT_GUNYAH:
		ret = HYP_VARIANT_GUNYAH;
		break;
	case (uint32_t)HYP_VARIANT_QUALCOMM:
		ret = HYP_VARIANT_QUALCOMM;
		break;
	default:
		// Invalid hyp_variant
		__builtin_trap();
	}
#else
	ret = (hyp_variant_t)val;
#endif

	return ret;
}

hyp_variant_result_t
hyp_variant_raw_cast_safe(uint32_t val)
{
	hyp_variant_result_t ret;

	switch (val) {
	case (uint32_t)HYP_VARIANT_UNKNOWN:
		ret = hyp_variant_result_ok(HYP_VARIANT_UNKNOWN);
		break;
	case (uint32_t)HYP_VARIANT_GUNYAH:
		ret = hyp_variant_result_ok(HYP_VARIANT_GUNYAH);
		break;
	case (uint32_t)HYP_VARIANT_QUALCOMM:
		ret = hyp_variant_result_ok(HYP_VARIANT_QUALCOMM);
		break;
	default:
		ret = hyp_variant_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
hyp_variant_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)HYP_VARIANT_UNKNOWN:
	case (uint32_t)HYP_VARIANT_GUNYAH:
	case (uint32_t)HYP_VARIANT_QUALCOMM:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

memextent_donate_type_t
memextent_donate_type_raw_cast(uint32_t val)
{
	memextent_donate_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_CHILD:
		ret = MEMEXTENT_DONATE_TYPE_TO_CHILD;
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PARENT:
		ret = MEMEXTENT_DONATE_TYPE_TO_PARENT;
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_SIBLING:
		ret = MEMEXTENT_DONATE_TYPE_TO_SIBLING;
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PROTECTED:
		ret = MEMEXTENT_DONATE_TYPE_TO_PROTECTED;
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_FROM_PROTECTED:
		ret = MEMEXTENT_DONATE_TYPE_FROM_PROTECTED;
		break;
	default:
		// Invalid memextent_donate_type
		__builtin_trap();
	}
#else
	ret = (memextent_donate_type_t)val;
#endif

	return ret;
}

memextent_donate_type_result_t
memextent_donate_type_raw_cast_safe(uint32_t val)
{
	memextent_donate_type_result_t ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_CHILD:
		ret = memextent_donate_type_result_ok(
			MEMEXTENT_DONATE_TYPE_TO_CHILD);
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PARENT:
		ret = memextent_donate_type_result_ok(
			MEMEXTENT_DONATE_TYPE_TO_PARENT);
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_SIBLING:
		ret = memextent_donate_type_result_ok(
			MEMEXTENT_DONATE_TYPE_TO_SIBLING);
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PROTECTED:
		ret = memextent_donate_type_result_ok(
			MEMEXTENT_DONATE_TYPE_TO_PROTECTED);
		break;
	case (uint32_t)MEMEXTENT_DONATE_TYPE_FROM_PROTECTED:
		ret = memextent_donate_type_result_ok(
			MEMEXTENT_DONATE_TYPE_FROM_PROTECTED);
		break;
	default:
		ret = memextent_donate_type_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
memextent_donate_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_CHILD:
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PARENT:
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_SIBLING:
	case (uint32_t)MEMEXTENT_DONATE_TYPE_TO_PROTECTED:
	case (uint32_t)MEMEXTENT_DONATE_TYPE_FROM_PROTECTED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

memextent_memtype_t
memextent_memtype_raw_cast(uint32_t val)
{
	memextent_memtype_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)MEMEXTENT_MEMTYPE_ANY:
		ret = MEMEXTENT_MEMTYPE_ANY;
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_DEVICE:
		ret = MEMEXTENT_MEMTYPE_DEVICE;
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_UNCACHED:
		ret = MEMEXTENT_MEMTYPE_UNCACHED;
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_CACHED:
		ret = MEMEXTENT_MEMTYPE_CACHED;
		break;
	default:
		// Invalid memextent_memtype
		__builtin_trap();
	}
#else
	ret = (memextent_memtype_t)val;
#endif

	return ret;
}

memextent_memtype_result_t
memextent_memtype_raw_cast_safe(uint32_t val)
{
	memextent_memtype_result_t ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_MEMTYPE_ANY:
		ret = memextent_memtype_result_ok(MEMEXTENT_MEMTYPE_ANY);
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_DEVICE:
		ret = memextent_memtype_result_ok(MEMEXTENT_MEMTYPE_DEVICE);
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_UNCACHED:
		ret = memextent_memtype_result_ok(MEMEXTENT_MEMTYPE_UNCACHED);
		break;
	case (uint32_t)MEMEXTENT_MEMTYPE_CACHED:
		ret = memextent_memtype_result_ok(MEMEXTENT_MEMTYPE_CACHED);
		break;
	default:
		ret = memextent_memtype_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
memextent_memtype_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_MEMTYPE_ANY:
	case (uint32_t)MEMEXTENT_MEMTYPE_DEVICE:
	case (uint32_t)MEMEXTENT_MEMTYPE_UNCACHED:
	case (uint32_t)MEMEXTENT_MEMTYPE_CACHED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

memextent_modify_op_t
memextent_modify_op_raw_cast(uint32_t val)
{
	memextent_modify_op_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)MEMEXTENT_MODIFY_OP_UNMAP_ALL:
		ret = MEMEXTENT_MODIFY_OP_UNMAP_ALL;
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_ZERO_RANGE:
		ret = MEMEXTENT_MODIFY_OP_ZERO_RANGE;
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE:
		ret = MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE;
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE:
		ret = MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE;
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET:
		ret = MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET;
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_SYNC_ALL:
		ret = MEMEXTENT_MODIFY_OP_SYNC_ALL;
		break;
	default:
		// Invalid memextent_modify_op
		__builtin_trap();
	}
#else
	ret = (memextent_modify_op_t)val;
#endif

	return ret;
}

memextent_modify_op_result_t
memextent_modify_op_raw_cast_safe(uint32_t val)
{
	memextent_modify_op_result_t ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_MODIFY_OP_UNMAP_ALL:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_UNMAP_ALL);
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_ZERO_RANGE:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_ZERO_RANGE);
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE);
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE);
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET);
		break;
	case (uint32_t)MEMEXTENT_MODIFY_OP_SYNC_ALL:
		ret = memextent_modify_op_result_ok(
			MEMEXTENT_MODIFY_OP_SYNC_ALL);
		break;
	default:
		ret = memextent_modify_op_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
memextent_modify_op_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_MODIFY_OP_UNMAP_ALL:
	case (uint32_t)MEMEXTENT_MODIFY_OP_ZERO_RANGE:
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_CLEAN_RANGE:
	case (uint32_t)MEMEXTENT_MODIFY_OP_CACHE_FLUSH_RANGE:
	case (uint32_t)MEMEXTENT_MODIFY_OP_SANITISE_ON_RESET:
	case (uint32_t)MEMEXTENT_MODIFY_OP_SYNC_ALL:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

memextent_type_t
memextent_type_raw_cast(uint32_t val)
{
	memextent_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)MEMEXTENT_TYPE_BASIC:
		ret = MEMEXTENT_TYPE_BASIC;
		break;
	case (uint32_t)MEMEXTENT_TYPE_SPARSE:
		ret = MEMEXTENT_TYPE_SPARSE;
		break;
	default:
		// Invalid memextent_type
		__builtin_trap();
	}
#else
	ret = (memextent_type_t)val;
#endif

	return ret;
}

memextent_type_result_t
memextent_type_raw_cast_safe(uint32_t val)
{
	memextent_type_result_t ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_TYPE_BASIC:
		ret = memextent_type_result_ok(MEMEXTENT_TYPE_BASIC);
		break;
	case (uint32_t)MEMEXTENT_TYPE_SPARSE:
		ret = memextent_type_result_ok(MEMEXTENT_TYPE_SPARSE);
		break;
	default:
		ret = memextent_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
memextent_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)MEMEXTENT_TYPE_BASIC:
	case (uint32_t)MEMEXTENT_TYPE_SPARSE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

partition_donate_type_t
partition_donate_type_raw_cast(uint32_t val)
{
	partition_donate_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)PARTITION_DONATE_TYPE_TO_PARTITION:
		ret = PARTITION_DONATE_TYPE_TO_PARTITION;
		break;
	case (uint32_t)PARTITION_DONATE_TYPE_ADD_HEAP:
		ret = PARTITION_DONATE_TYPE_ADD_HEAP;
		break;
	case (uint32_t)PARTITION_DONATE_TYPE_REMOVE_HEAP:
		ret = PARTITION_DONATE_TYPE_REMOVE_HEAP;
		break;
	default:
		// Invalid partition_donate_type
		__builtin_trap();
	}
#else
	ret = (partition_donate_type_t)val;
#endif

	return ret;
}

partition_donate_type_result_t
partition_donate_type_raw_cast_safe(uint32_t val)
{
	partition_donate_type_result_t ret;

	switch (val) {
	case (uint32_t)PARTITION_DONATE_TYPE_TO_PARTITION:
		ret = partition_donate_type_result_ok(
			PARTITION_DONATE_TYPE_TO_PARTITION);
		break;
	case (uint32_t)PARTITION_DONATE_TYPE_ADD_HEAP:
		ret = partition_donate_type_result_ok(
			PARTITION_DONATE_TYPE_ADD_HEAP);
		break;
	case (uint32_t)PARTITION_DONATE_TYPE_REMOVE_HEAP:
		ret = partition_donate_type_result_ok(
			PARTITION_DONATE_TYPE_REMOVE_HEAP);
		break;
	default:
		ret = partition_donate_type_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
partition_donate_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)PARTITION_DONATE_TYPE_TO_PARTITION:
	case (uint32_t)PARTITION_DONATE_TYPE_ADD_HEAP:
	case (uint32_t)PARTITION_DONATE_TYPE_REMOVE_HEAP:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

partition_query_type_t
partition_query_type_raw_cast(uint32_t val)
{
	partition_query_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_IS_FREE:
		ret = PARTITION_QUERY_TYPE_HEAP_IS_FREE;
		break;
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_STATS:
		ret = PARTITION_QUERY_TYPE_HEAP_STATS;
		break;
	default:
		// Invalid partition_query_type
		__builtin_trap();
	}
#else
	ret = (partition_query_type_t)val;
#endif

	return ret;
}

partition_query_type_result_t
partition_query_type_raw_cast_safe(uint32_t val)
{
	partition_query_type_result_t ret;

	switch (val) {
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_IS_FREE:
		ret = partition_query_type_result_ok(
			PARTITION_QUERY_TYPE_HEAP_IS_FREE);
		break;
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_STATS:
		ret = partition_query_type_result_ok(
			PARTITION_QUERY_TYPE_HEAP_STATS);
		break;
	default:
		ret = partition_query_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
partition_query_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_IS_FREE:
	case (uint32_t)PARTITION_QUERY_TYPE_HEAP_STATS:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

pci_host_lockdown_state_t
pci_host_lockdown_state_raw_cast(uint32_t val)
{
	pci_host_lockdown_state_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_PERMISSIVE:
		ret = PCI_HOST_LOCKDOWN_STATE_PERMISSIVE;
		break;
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_SCANNING:
		ret = PCI_HOST_LOCKDOWN_STATE_SCANNING;
		break;
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_RESTRICTED:
		ret = PCI_HOST_LOCKDOWN_STATE_RESTRICTED;
		break;
	default:
		// Invalid pci_host_lockdown_state
		__builtin_trap();
	}
#else
	ret = (pci_host_lockdown_state_t)val;
#endif

	return ret;
}

pci_host_lockdown_state_result_t
pci_host_lockdown_state_raw_cast_safe(uint32_t val)
{
	pci_host_lockdown_state_result_t ret;

	switch (val) {
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_PERMISSIVE:
		ret = pci_host_lockdown_state_result_ok(
			PCI_HOST_LOCKDOWN_STATE_PERMISSIVE);
		break;
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_SCANNING:
		ret = pci_host_lockdown_state_result_ok(
			PCI_HOST_LOCKDOWN_STATE_SCANNING);
		break;
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_RESTRICTED:
		ret = pci_host_lockdown_state_result_ok(
			PCI_HOST_LOCKDOWN_STATE_RESTRICTED);
		break;
	default:
		ret = pci_host_lockdown_state_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
pci_host_lockdown_state_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_PERMISSIVE:
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_SCANNING:
	case (uint32_t)PCI_HOST_LOCKDOWN_STATE_RESTRICTED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

pgtable_access_t
pgtable_access_raw_cast(uint32_t val)
{
	pgtable_access_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)PGTABLE_ACCESS_NONE:
		ret = PGTABLE_ACCESS_NONE;
		break;
	case (uint32_t)PGTABLE_ACCESS_X:
		ret = PGTABLE_ACCESS_X;
		break;
	case (uint32_t)PGTABLE_ACCESS_W:
		ret = PGTABLE_ACCESS_W;
		break;
	case (uint32_t)PGTABLE_ACCESS_R:
		ret = PGTABLE_ACCESS_R;
		break;
	case (uint32_t)PGTABLE_ACCESS_RX:
		ret = PGTABLE_ACCESS_RX;
		break;
	case (uint32_t)PGTABLE_ACCESS_RW:
		ret = PGTABLE_ACCESS_RW;
		break;
	case (uint32_t)PGTABLE_ACCESS_RWX:
		ret = PGTABLE_ACCESS_RWX;
		break;
	default:
		// Invalid pgtable_access
		__builtin_trap();
	}
#else
	ret = (pgtable_access_t)val;
#endif

	return ret;
}

pgtable_access_result_t
pgtable_access_raw_cast_safe(uint32_t val)
{
	pgtable_access_result_t ret;

	switch (val) {
	case (uint32_t)PGTABLE_ACCESS_NONE:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_NONE);
		break;
	case (uint32_t)PGTABLE_ACCESS_X:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_X);
		break;
	case (uint32_t)PGTABLE_ACCESS_W:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_W);
		break;
	case (uint32_t)PGTABLE_ACCESS_R:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_R);
		break;
	case (uint32_t)PGTABLE_ACCESS_RX:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_RX);
		break;
	case (uint32_t)PGTABLE_ACCESS_RW:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_RW);
		break;
	case (uint32_t)PGTABLE_ACCESS_RWX:
		ret = pgtable_access_result_ok(PGTABLE_ACCESS_RWX);
		break;
	default:
		ret = pgtable_access_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
pgtable_access_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)PGTABLE_ACCESS_NONE:
	case (uint32_t)PGTABLE_ACCESS_X:
	case (uint32_t)PGTABLE_ACCESS_W:
	case (uint32_t)PGTABLE_ACCESS_R:
	case (uint32_t)PGTABLE_ACCESS_RX:
	case (uint32_t)PGTABLE_ACCESS_RW:
	case (uint32_t)PGTABLE_ACCESS_RWX:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

pgtable_vm_memtype_t
pgtable_vm_memtype_raw_cast(uint32_t val)
{
	pgtable_vm_memtype_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE:
		ret = PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRE:
		ret = PGTABLE_VM_MEMTYPE_DEVICE_NGNRE;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGRE:
		ret = PGTABLE_VM_MEMTYPE_DEVICE_NGRE;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_GRE:
		ret = PGTABLE_VM_MEMTYPE_DEVICE_GRE;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_NC:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_NC;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WT:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_WT;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT;
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WB:
		ret = PGTABLE_VM_MEMTYPE_NORMAL_WB;
		break;
	default:
		// Invalid pgtable_vm_memtype
		__builtin_trap();
	}
#else
	ret = (pgtable_vm_memtype_t)val;
#endif

	return ret;
}

pgtable_vm_memtype_result_t
pgtable_vm_memtype_raw_cast_safe(uint32_t val)
{
	pgtable_vm_memtype_result_t ret;

	switch (val) {
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRE:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_DEVICE_NGNRE);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGRE:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_DEVICE_NGRE);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_GRE:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_DEVICE_GRE);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_NC:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_NC);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WT:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_WT);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT);
		break;
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WB:
		ret = pgtable_vm_memtype_result_ok(
			PGTABLE_VM_MEMTYPE_NORMAL_WB);
		break;
	default:
		ret = pgtable_vm_memtype_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
pgtable_vm_memtype_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRNE:
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGNRE:
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_NGRE:
	case (uint32_t)PGTABLE_VM_MEMTYPE_DEVICE_GRE:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_NC:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWT:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_ONC_IWB:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_INC:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WT:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWT_IWB:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_INC:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_OWB_IWT:
	case (uint32_t)PGTABLE_VM_MEMTYPE_NORMAL_WB:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

scheduler_variant_t
scheduler_variant_raw_cast(uint32_t val)
{
	scheduler_variant_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SCHEDULER_VARIANT_TRIVIAL:
		ret = SCHEDULER_VARIANT_TRIVIAL;
		break;
	case (uint32_t)SCHEDULER_VARIANT_FPRR:
		ret = SCHEDULER_VARIANT_FPRR;
		break;
	default:
		// Invalid scheduler_variant
		__builtin_trap();
	}
#else
	ret = (scheduler_variant_t)val;
#endif

	return ret;
}

scheduler_variant_result_t
scheduler_variant_raw_cast_safe(uint32_t val)
{
	scheduler_variant_result_t ret;

	switch (val) {
	case (uint32_t)SCHEDULER_VARIANT_TRIVIAL:
		ret = scheduler_variant_result_ok(SCHEDULER_VARIANT_TRIVIAL);
		break;
	case (uint32_t)SCHEDULER_VARIANT_FPRR:
		ret = scheduler_variant_result_ok(SCHEDULER_VARIANT_FPRR);
		break;
	default:
		ret = scheduler_variant_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
scheduler_variant_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SCHEDULER_VARIANT_TRIVIAL:
	case (uint32_t)SCHEDULER_VARIANT_FPRR:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

scheduler_yield_hint_t
scheduler_yield_hint_raw_cast(uint32_t val)
{
	scheduler_yield_hint_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD:
		ret = SCHEDULER_YIELD_HINT_YIELD;
		break;
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_TO_THREAD:
		ret = SCHEDULER_YIELD_HINT_YIELD_TO_THREAD;
		break;
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_LOWER:
		ret = SCHEDULER_YIELD_HINT_YIELD_LOWER;
		break;
	default:
		// Invalid scheduler_yield_hint
		__builtin_trap();
	}
#else
	ret = (scheduler_yield_hint_t)val;
#endif

	return ret;
}

scheduler_yield_hint_result_t
scheduler_yield_hint_raw_cast_safe(uint32_t val)
{
	scheduler_yield_hint_result_t ret;

	switch (val) {
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD:
		ret = scheduler_yield_hint_result_ok(
			SCHEDULER_YIELD_HINT_YIELD);
		break;
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_TO_THREAD:
		ret = scheduler_yield_hint_result_ok(
			SCHEDULER_YIELD_HINT_YIELD_TO_THREAD);
		break;
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_LOWER:
		ret = scheduler_yield_hint_result_ok(
			SCHEDULER_YIELD_HINT_YIELD_LOWER);
		break;
	default:
		ret = scheduler_yield_hint_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
scheduler_yield_hint_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD:
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_TO_THREAD:
	case (uint32_t)SCHEDULER_YIELD_HINT_YIELD_LOWER:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

sdei_error_reason_t
sdei_error_reason_raw_cast(uint32_t val)
{
	sdei_error_reason_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SDEI_ERROR_REASON_UNKNOWN:
		ret = SDEI_ERROR_REASON_UNKNOWN;
		break;
	case (uint32_t)SDEI_ERROR_REASON_SENT_BY_USER:
		ret = SDEI_ERROR_REASON_SENT_BY_USER;
		break;
	case (uint32_t)SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE:
		ret = SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE;
		break;
	default:
		// Invalid sdei_error_reason
		__builtin_trap();
	}
#else
	ret = (sdei_error_reason_t)val;
#endif

	return ret;
}

sdei_error_reason_result_t
sdei_error_reason_raw_cast_safe(uint32_t val)
{
	sdei_error_reason_result_t ret;

	switch (val) {
	case (uint32_t)SDEI_ERROR_REASON_UNKNOWN:
		ret = sdei_error_reason_result_ok(SDEI_ERROR_REASON_UNKNOWN);
		break;
	case (uint32_t)SDEI_ERROR_REASON_SENT_BY_USER:
		ret = sdei_error_reason_result_ok(
			SDEI_ERROR_REASON_SENT_BY_USER);
		break;
	case (uint32_t)SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE:
		ret = sdei_error_reason_result_ok(
			SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE);
		break;
	default:
		ret = sdei_error_reason_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
sdei_error_reason_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SDEI_ERROR_REASON_UNKNOWN:
	case (uint32_t)SDEI_ERROR_REASON_SENT_BY_USER:
	case (uint32_t)SDEI_ERROR_REASON_VIRTUAL_WATCHDOG_BITE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

smccc_arch_function_t
smccc_arch_function_raw_cast(uint32_t val)
{
	smccc_arch_function_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SMCCC_ARCH_FUNCTION_VERSION:
		ret = SMCCC_ARCH_FUNCTION_VERSION;
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_FEATURES:
		ret = SMCCC_ARCH_FUNCTION_ARCH_FEATURES;
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_SOC_ID:
		ret = SMCCC_ARCH_FUNCTION_ARCH_SOC_ID;
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2:
		ret = SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2;
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1:
		ret = SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1;
		break;
	default:
		// Invalid smccc_arch_function
		__builtin_trap();
	}
#else
	ret = (smccc_arch_function_t)val;
#endif

	return ret;
}

smccc_arch_function_result_t
smccc_arch_function_raw_cast_safe(uint32_t val)
{
	smccc_arch_function_result_t ret;

	switch (val) {
	case (uint32_t)SMCCC_ARCH_FUNCTION_VERSION:
		ret = smccc_arch_function_result_ok(
			SMCCC_ARCH_FUNCTION_VERSION);
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_FEATURES:
		ret = smccc_arch_function_result_ok(
			SMCCC_ARCH_FUNCTION_ARCH_FEATURES);
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_SOC_ID:
		ret = smccc_arch_function_result_ok(
			SMCCC_ARCH_FUNCTION_ARCH_SOC_ID);
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2:
		ret = smccc_arch_function_result_ok(
			SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2);
		break;
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1:
		ret = smccc_arch_function_result_ok(
			SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1);
		break;
	default:
		ret = smccc_arch_function_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
smccc_arch_function_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SMCCC_ARCH_FUNCTION_VERSION:
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_FEATURES:
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_SOC_ID:
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_2:
	case (uint32_t)SMCCC_ARCH_FUNCTION_ARCH_WORKAROUND_1:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

smccc_owner_id_t
smccc_owner_id_raw_cast(uint32_t val)
{
	smccc_owner_id_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SMCCC_OWNER_ID_ARCH:
		ret = SMCCC_OWNER_ID_ARCH;
		break;
	case (uint32_t)SMCCC_OWNER_ID_CPU:
		ret = SMCCC_OWNER_ID_CPU;
		break;
	case (uint32_t)SMCCC_OWNER_ID_SIP:
		ret = SMCCC_OWNER_ID_SIP;
		break;
	case (uint32_t)SMCCC_OWNER_ID_OEM:
		ret = SMCCC_OWNER_ID_OEM;
		break;
	case (uint32_t)SMCCC_OWNER_ID_STANDARD:
		ret = SMCCC_OWNER_ID_STANDARD;
		break;
	case (uint32_t)SMCCC_OWNER_ID_STANDARD_HYP:
		ret = SMCCC_OWNER_ID_STANDARD_HYP;
		break;
	case (uint32_t)SMCCC_OWNER_ID_VENDOR_HYP:
		ret = SMCCC_OWNER_ID_VENDOR_HYP;
		break;
	default:
		// Invalid smccc_owner_id
		__builtin_trap();
	}
#else
	ret = (smccc_owner_id_t)val;
#endif

	return ret;
}

smccc_owner_id_result_t
smccc_owner_id_raw_cast_safe(uint32_t val)
{
	smccc_owner_id_result_t ret;

	switch (val) {
	case (uint32_t)SMCCC_OWNER_ID_ARCH:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_ARCH);
		break;
	case (uint32_t)SMCCC_OWNER_ID_CPU:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_CPU);
		break;
	case (uint32_t)SMCCC_OWNER_ID_SIP:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_SIP);
		break;
	case (uint32_t)SMCCC_OWNER_ID_OEM:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_OEM);
		break;
	case (uint32_t)SMCCC_OWNER_ID_STANDARD:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_STANDARD);
		break;
	case (uint32_t)SMCCC_OWNER_ID_STANDARD_HYP:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_STANDARD_HYP);
		break;
	case (uint32_t)SMCCC_OWNER_ID_VENDOR_HYP:
		ret = smccc_owner_id_result_ok(SMCCC_OWNER_ID_VENDOR_HYP);
		break;
	default:
		ret = smccc_owner_id_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
smccc_owner_id_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SMCCC_OWNER_ID_ARCH:
	case (uint32_t)SMCCC_OWNER_ID_CPU:
	case (uint32_t)SMCCC_OWNER_ID_SIP:
	case (uint32_t)SMCCC_OWNER_ID_OEM:
	case (uint32_t)SMCCC_OWNER_ID_STANDARD:
	case (uint32_t)SMCCC_OWNER_ID_STANDARD_HYP:
	case (uint32_t)SMCCC_OWNER_ID_VENDOR_HYP:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

smccc_standard_hyp_function_t
smccc_standard_hyp_function_raw_cast(uint32_t val)
{
	smccc_standard_hyp_function_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT:
		ret = SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT;
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_UID:
		ret = SMCCC_STANDARD_HYP_FUNCTION_CALL_UID;
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_REVISION:
		ret = SMCCC_STANDARD_HYP_FUNCTION_REVISION;
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES:
		ret = SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES;
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST:
		ret = SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST;
		break;
	default:
		// Invalid smccc_standard_hyp_function
		__builtin_trap();
	}
#else
	ret = (smccc_standard_hyp_function_t)val;
#endif

	return ret;
}

smccc_standard_hyp_function_result_t
smccc_standard_hyp_function_raw_cast_safe(uint32_t val)
{
	smccc_standard_hyp_function_result_t ret;

	switch (val) {
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT:
		ret = smccc_standard_hyp_function_result_ok(
			SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT);
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_UID:
		ret = smccc_standard_hyp_function_result_ok(
			SMCCC_STANDARD_HYP_FUNCTION_CALL_UID);
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_REVISION:
		ret = smccc_standard_hyp_function_result_ok(
			SMCCC_STANDARD_HYP_FUNCTION_REVISION);
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES:
		ret = smccc_standard_hyp_function_result_ok(
			SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES);
		break;
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST:
		ret = smccc_standard_hyp_function_result_ok(
			SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST);
		break;
	default:
		ret = smccc_standard_hyp_function_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
smccc_standard_hyp_function_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_COUNT:
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_CALL_UID:
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_REVISION:
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_FEATURES:
	case (uint32_t)SMCCC_STANDARD_HYP_FUNCTION_PV_TIME_ST:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

smccc_vendor_hyp_function_t
smccc_vendor_hyp_function_raw_cast(uint32_t val)
{
	smccc_vendor_hyp_function_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT:
		ret = SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT;
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_UID:
		ret = SMCCC_VENDOR_HYP_FUNCTION_CALL_UID;
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_REVISION:
		ret = SMCCC_VENDOR_HYP_FUNCTION_REVISION;
		break;
	default:
		// Invalid smccc_vendor_hyp_function
		__builtin_trap();
	}
#else
	ret = (smccc_vendor_hyp_function_t)val;
#endif

	return ret;
}

smccc_vendor_hyp_function_result_t
smccc_vendor_hyp_function_raw_cast_safe(uint32_t val)
{
	smccc_vendor_hyp_function_result_t ret;

	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT:
		ret = smccc_vendor_hyp_function_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT);
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_UID:
		ret = smccc_vendor_hyp_function_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_CALL_UID);
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_REVISION:
		ret = smccc_vendor_hyp_function_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_REVISION);
		break;
	default:
		ret = smccc_vendor_hyp_function_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
smccc_vendor_hyp_function_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_COUNT:
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CALL_UID:
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_REVISION:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

smccc_vendor_hyp_function_class_t
smccc_vendor_hyp_function_class_raw_cast(uint32_t val)
{
	smccc_vendor_hyp_function_class_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL:
		ret = SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL;
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL:
		ret = SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL;
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE:
		ret = SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE;
		break;
	default:
		// Invalid smccc_vendor_hyp_function_class
		__builtin_trap();
	}
#else
	ret = (smccc_vendor_hyp_function_class_t)val;
#endif

	return ret;
}

smccc_vendor_hyp_function_class_result_t
smccc_vendor_hyp_function_class_raw_cast_safe(uint32_t val)
{
	smccc_vendor_hyp_function_class_result_t ret;

	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL:
		ret = smccc_vendor_hyp_function_class_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL);
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL:
		ret = smccc_vendor_hyp_function_class_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL);
		break;
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE:
		ret = smccc_vendor_hyp_function_class_result_ok(
			SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE);
		break;
	default:
		ret = smccc_vendor_hyp_function_class_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
smccc_vendor_hyp_function_class_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_PLATFORM_CALL:
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_HYPERCALL:
	case (uint32_t)SMCCC_VENDOR_HYP_FUNCTION_CLASS_SERVICE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

trace_class_t
trace_class_raw_cast(uint32_t val)
{
	trace_class_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)TRACE_CLASS_ERROR:
		ret = TRACE_CLASS_ERROR;
		break;
	case (uint32_t)TRACE_CLASS_DEBUG:
		ret = TRACE_CLASS_DEBUG;
		break;
	case (uint32_t)TRACE_CLASS_INFO:
		ret = TRACE_CLASS_INFO;
		break;
	case (uint32_t)TRACE_CLASS_USER:
		ret = TRACE_CLASS_USER;
		break;
	case (uint32_t)TRACE_CLASS_MEMDB:
		ret = TRACE_CLASS_MEMDB;
		break;
	case (uint32_t)TRACE_CLASS_LOG_BUFFER:
		ret = TRACE_CLASS_LOG_BUFFER;
		break;
	case (uint32_t)TRACE_CLASS_TRACE_LOG_BUFFER:
		ret = TRACE_CLASS_TRACE_LOG_BUFFER;
		break;
	case (uint32_t)TRACE_CLASS_VGIC:
		ret = TRACE_CLASS_VGIC;
		break;
	case (uint32_t)TRACE_CLASS_VGIC_DEBUG:
		ret = TRACE_CLASS_VGIC_DEBUG;
		break;
	case (uint32_t)TRACE_CLASS_VGIC_ITS:
		ret = TRACE_CLASS_VGIC_ITS;
		break;
	default:
		// Invalid trace_class
		__builtin_trap();
	}
#else
	ret = (trace_class_t)val;
#endif

	return ret;
}

trace_class_result_t
trace_class_raw_cast_safe(uint32_t val)
{
	trace_class_result_t ret;

	switch (val) {
	case (uint32_t)TRACE_CLASS_ERROR:
		ret = trace_class_result_ok(TRACE_CLASS_ERROR);
		break;
	case (uint32_t)TRACE_CLASS_DEBUG:
		ret = trace_class_result_ok(TRACE_CLASS_DEBUG);
		break;
	case (uint32_t)TRACE_CLASS_INFO:
		ret = trace_class_result_ok(TRACE_CLASS_INFO);
		break;
	case (uint32_t)TRACE_CLASS_USER:
		ret = trace_class_result_ok(TRACE_CLASS_USER);
		break;
	case (uint32_t)TRACE_CLASS_MEMDB:
		ret = trace_class_result_ok(TRACE_CLASS_MEMDB);
		break;
	case (uint32_t)TRACE_CLASS_LOG_BUFFER:
		ret = trace_class_result_ok(TRACE_CLASS_LOG_BUFFER);
		break;
	case (uint32_t)TRACE_CLASS_TRACE_LOG_BUFFER:
		ret = trace_class_result_ok(TRACE_CLASS_TRACE_LOG_BUFFER);
		break;
	case (uint32_t)TRACE_CLASS_VGIC:
		ret = trace_class_result_ok(TRACE_CLASS_VGIC);
		break;
	case (uint32_t)TRACE_CLASS_VGIC_DEBUG:
		ret = trace_class_result_ok(TRACE_CLASS_VGIC_DEBUG);
		break;
	case (uint32_t)TRACE_CLASS_VGIC_ITS:
		ret = trace_class_result_ok(TRACE_CLASS_VGIC_ITS);
		break;
	default:
		ret = trace_class_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
trace_class_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)TRACE_CLASS_ERROR:
	case (uint32_t)TRACE_CLASS_DEBUG:
	case (uint32_t)TRACE_CLASS_INFO:
	case (uint32_t)TRACE_CLASS_USER:
	case (uint32_t)TRACE_CLASS_MEMDB:
	case (uint32_t)TRACE_CLASS_LOG_BUFFER:
	case (uint32_t)TRACE_CLASS_TRACE_LOG_BUFFER:
	case (uint32_t)TRACE_CLASS_VGIC:
	case (uint32_t)TRACE_CLASS_VGIC_DEBUG:
	case (uint32_t)TRACE_CLASS_VGIC_ITS:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

trace_configure_parameter_t
trace_configure_parameter_raw_cast(uint32_t val)
{
	trace_configure_parameter_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS:
		ret = TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS;
		break;
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE:
		ret = TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE;
		break;
	default:
		// Invalid trace_configure_parameter
		__builtin_trap();
	}
#else
	ret = (trace_configure_parameter_t)val;
#endif

	return ret;
}

trace_configure_parameter_result_t
trace_configure_parameter_raw_cast_safe(uint32_t val)
{
	trace_configure_parameter_result_t ret;

	switch (val) {
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS:
		ret = trace_configure_parameter_result_ok(
			TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS);
		break;
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE:
		ret = trace_configure_parameter_result_ok(
			TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE);
		break;
	default:
		ret = trace_configure_parameter_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
trace_configure_parameter_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_CLASS_FLAGS:
	case (uint32_t)TRACE_CONFIGURE_PARAMETER_NOTIFY_ENABLE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_affinity_type_t
vcpu_affinity_type_raw_cast(int32_t val)
{
	vcpu_affinity_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (int32_t)VCPU_AFFINITY_TYPE_CPU_INDEX:
		ret = VCPU_AFFINITY_TYPE_CPU_INDEX;
		break;
	case (int32_t)VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX:
		ret = VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX;
		break;
	default:
		// Invalid vcpu_affinity_type
		__builtin_trap();
	}
#else
	ret = (vcpu_affinity_type_t)val;
#endif

	return ret;
}

vcpu_affinity_type_result_t
vcpu_affinity_type_raw_cast_safe(int32_t val)
{
	vcpu_affinity_type_result_t ret;

	switch (val) {
	case (int32_t)VCPU_AFFINITY_TYPE_CPU_INDEX:
		ret = vcpu_affinity_type_result_ok(
			VCPU_AFFINITY_TYPE_CPU_INDEX);
		break;
	case (int32_t)VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX:
		ret = vcpu_affinity_type_result_ok(
			VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX);
		break;
	default:
		ret = vcpu_affinity_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_affinity_type_raw_is_valid(int32_t val)
{
	bool ret;

	switch (val) {
	case (int32_t)VCPU_AFFINITY_TYPE_CPU_INDEX:
	case (int32_t)VCPU_AFFINITY_TYPE_PLATFORM_CPU_INDEX:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_local_virq_type_t
vcpu_local_virq_type_raw_cast(uint32_t val)
{
	vcpu_local_virq_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_RESERVED:
		ret = VCPU_LOCAL_VIRQ_TYPE_RESERVED;
		break;
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER:
		ret = VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER;
		break;
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER:
		ret = VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER;
		break;
	default:
		// Invalid vcpu_local_virq_type
		__builtin_trap();
	}
#else
	ret = (vcpu_local_virq_type_t)val;
#endif

	return ret;
}

vcpu_local_virq_type_result_t
vcpu_local_virq_type_raw_cast_safe(uint32_t val)
{
	vcpu_local_virq_type_result_t ret;

	switch (val) {
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_RESERVED:
		ret = vcpu_local_virq_type_result_ok(
			VCPU_LOCAL_VIRQ_TYPE_RESERVED);
		break;
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER:
		ret = vcpu_local_virq_type_result_ok(
			VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER);
		break;
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER:
		ret = vcpu_local_virq_type_result_ok(
			VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER);
		break;
	default:
		ret = vcpu_local_virq_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_local_virq_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_RESERVED:
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_VIRTUAL_TIMER:
	case (uint32_t)VCPU_LOCAL_VIRQ_TYPE_PHYSICAL_TIMER:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_register_set_t
vcpu_register_set_raw_cast(uint32_t val)
{
	vcpu_register_set_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VCPU_REGISTER_SET_X:
		ret = VCPU_REGISTER_SET_X;
		break;
	case (uint32_t)VCPU_REGISTER_SET_PC:
		ret = VCPU_REGISTER_SET_PC;
		break;
	case (uint32_t)VCPU_REGISTER_SET_SP_EL:
		ret = VCPU_REGISTER_SET_SP_EL;
		break;
	default:
		// Invalid vcpu_register_set
		__builtin_trap();
	}
#else
	ret = (vcpu_register_set_t)val;
#endif

	return ret;
}

vcpu_register_set_result_t
vcpu_register_set_raw_cast_safe(uint32_t val)
{
	vcpu_register_set_result_t ret;

	switch (val) {
	case (uint32_t)VCPU_REGISTER_SET_X:
		ret = vcpu_register_set_result_ok(VCPU_REGISTER_SET_X);
		break;
	case (uint32_t)VCPU_REGISTER_SET_PC:
		ret = vcpu_register_set_result_ok(VCPU_REGISTER_SET_PC);
		break;
	case (uint32_t)VCPU_REGISTER_SET_SP_EL:
		ret = vcpu_register_set_result_ok(VCPU_REGISTER_SET_SP_EL);
		break;
	default:
		ret = vcpu_register_set_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_register_set_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VCPU_REGISTER_SET_X:
	case (uint32_t)VCPU_REGISTER_SET_PC:
	case (uint32_t)VCPU_REGISTER_SET_SP_EL:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_run_state_t
vcpu_run_state_raw_cast(uint32_t val)
{
	vcpu_run_state_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VCPU_RUN_STATE_READY:
		ret = VCPU_RUN_STATE_READY;
		break;
	case (uint32_t)VCPU_RUN_STATE_EXPECTS_WAKEUP:
		ret = VCPU_RUN_STATE_EXPECTS_WAKEUP;
		break;
	case (uint32_t)VCPU_RUN_STATE_POWERED_OFF:
		ret = VCPU_RUN_STATE_POWERED_OFF;
		break;
	case (uint32_t)VCPU_RUN_STATE_BLOCKED:
		ret = VCPU_RUN_STATE_BLOCKED;
		break;
	case (uint32_t)VCPU_RUN_STATE_FAULT:
		ret = VCPU_RUN_STATE_FAULT;
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ:
		ret = VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ;
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE:
		ret = VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE;
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT:
		ret = VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT;
		break;
	case (uint32_t)VCPU_RUN_STATE_PSCI_SYSTEM_RESET:
		ret = VCPU_RUN_STATE_PSCI_SYSTEM_RESET;
		break;
	default:
		// Invalid vcpu_run_state
		__builtin_trap();
	}
#else
	ret = (vcpu_run_state_t)val;
#endif

	return ret;
}

vcpu_run_state_result_t
vcpu_run_state_raw_cast_safe(uint32_t val)
{
	vcpu_run_state_result_t ret;

	switch (val) {
	case (uint32_t)VCPU_RUN_STATE_READY:
		ret = vcpu_run_state_result_ok(VCPU_RUN_STATE_READY);
		break;
	case (uint32_t)VCPU_RUN_STATE_EXPECTS_WAKEUP:
		ret = vcpu_run_state_result_ok(VCPU_RUN_STATE_EXPECTS_WAKEUP);
		break;
	case (uint32_t)VCPU_RUN_STATE_POWERED_OFF:
		ret = vcpu_run_state_result_ok(VCPU_RUN_STATE_POWERED_OFF);
		break;
	case (uint32_t)VCPU_RUN_STATE_BLOCKED:
		ret = vcpu_run_state_result_ok(VCPU_RUN_STATE_BLOCKED);
		break;
	case (uint32_t)VCPU_RUN_STATE_FAULT:
		ret = vcpu_run_state_result_ok(VCPU_RUN_STATE_FAULT);
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ:
		ret = vcpu_run_state_result_ok(
			VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ);
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE:
		ret = vcpu_run_state_result_ok(
			VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE);
		break;
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT:
		ret = vcpu_run_state_result_ok(
			VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT);
		break;
	case (uint32_t)VCPU_RUN_STATE_PSCI_SYSTEM_RESET:
		ret = vcpu_run_state_result_ok(
			VCPU_RUN_STATE_PSCI_SYSTEM_RESET);
		break;
	default:
		ret = vcpu_run_state_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_run_state_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VCPU_RUN_STATE_READY:
	case (uint32_t)VCPU_RUN_STATE_EXPECTS_WAKEUP:
	case (uint32_t)VCPU_RUN_STATE_POWERED_OFF:
	case (uint32_t)VCPU_RUN_STATE_BLOCKED:
	case (uint32_t)VCPU_RUN_STATE_FAULT:
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_READ:
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_VMMIO_WRITE:
	case (uint32_t)VCPU_RUN_STATE_ADDRSPACE_PAGE_FAULT:
	case (uint32_t)VCPU_RUN_STATE_PSCI_SYSTEM_RESET:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_run_wakeup_from_state_t
vcpu_run_wakeup_from_state_raw_cast(uint32_t val)
{
	vcpu_run_wakeup_from_state_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED:
		ret = VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED;
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND:
		ret = VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND;
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND:
		ret = VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND;
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_WFI:
		ret = VCPU_RUN_WAKEUP_FROM_STATE_WFI;
		break;
	default:
		// Invalid vcpu_run_wakeup_from_state
		__builtin_trap();
	}
#else
	ret = (vcpu_run_wakeup_from_state_t)val;
#endif

	return ret;
}

vcpu_run_wakeup_from_state_result_t
vcpu_run_wakeup_from_state_raw_cast_safe(uint32_t val)
{
	vcpu_run_wakeup_from_state_result_t ret;

	switch (val) {
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED:
		ret = vcpu_run_wakeup_from_state_result_ok(
			VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED);
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND:
		ret = vcpu_run_wakeup_from_state_result_ok(
			VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND);
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND:
		ret = vcpu_run_wakeup_from_state_result_ok(
			VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND);
		break;
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_WFI:
		ret = vcpu_run_wakeup_from_state_result_ok(
			VCPU_RUN_WAKEUP_FROM_STATE_WFI);
		break;
	default:
		ret = vcpu_run_wakeup_from_state_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_run_wakeup_from_state_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_UNSPECIFIED:
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_CPU_SUSPEND:
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_PSCI_SYSTEM_SUSPEND:
	case (uint32_t)VCPU_RUN_WAKEUP_FROM_STATE_WFI:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vcpu_virq_type_t
vcpu_virq_type_raw_cast(uint32_t val)
{
	vcpu_virq_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP:
		ret = VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP;
		break;
	case (uint32_t)VCPU_VIRQ_TYPE_HALT:
		ret = VCPU_VIRQ_TYPE_HALT;
		break;
	default:
		// Invalid vcpu_virq_type
		__builtin_trap();
	}
#else
	ret = (vcpu_virq_type_t)val;
#endif

	return ret;
}

vcpu_virq_type_result_t
vcpu_virq_type_raw_cast_safe(uint32_t val)
{
	vcpu_virq_type_result_t ret;

	switch (val) {
	case (uint32_t)VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP:
		ret = vcpu_virq_type_result_ok(VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP);
		break;
	case (uint32_t)VCPU_VIRQ_TYPE_HALT:
		ret = vcpu_virq_type_result_ok(VCPU_VIRQ_TYPE_HALT);
		break;
	default:
		ret = vcpu_virq_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vcpu_virq_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VCPU_VIRQ_TYPE_VCPU_RUN_WAKEUP:
	case (uint32_t)VCPU_VIRQ_TYPE_HALT:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

virtio_device_type_t
virtio_device_type_raw_cast(uint32_t val)
{
	virtio_device_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VIRTIO_DEVICE_TYPE_INVALID:
		ret = VIRTIO_DEVICE_TYPE_INVALID;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_NETWORK:
		ret = VIRTIO_DEVICE_TYPE_NETWORK;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_BLOCK:
		ret = VIRTIO_DEVICE_TYPE_BLOCK;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_CONSOLE:
		ret = VIRTIO_DEVICE_TYPE_CONSOLE;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_BALLOON:
		ret = VIRTIO_DEVICE_TYPE_BALLOON;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_GPU:
		ret = VIRTIO_DEVICE_TYPE_GPU;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_INPUT:
		ret = VIRTIO_DEVICE_TYPE_INPUT;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_SOCKET:
		ret = VIRTIO_DEVICE_TYPE_SOCKET;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_IOMMU:
		ret = VIRTIO_DEVICE_TYPE_IOMMU;
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_MEMORY:
		ret = VIRTIO_DEVICE_TYPE_MEMORY;
		break;
	default:
		// Invalid virtio_device_type
		__builtin_trap();
	}
#else
	ret = (virtio_device_type_t)val;
#endif

	return ret;
}

virtio_device_type_result_t
virtio_device_type_raw_cast_safe(uint32_t val)
{
	virtio_device_type_result_t ret;

	switch (val) {
	case (uint32_t)VIRTIO_DEVICE_TYPE_INVALID:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_INVALID);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_NETWORK:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_NETWORK);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_BLOCK:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_BLOCK);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_CONSOLE:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_CONSOLE);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_BALLOON:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_BALLOON);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_GPU:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_GPU);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_INPUT:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_INPUT);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_SOCKET:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_SOCKET);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_IOMMU:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_IOMMU);
		break;
	case (uint32_t)VIRTIO_DEVICE_TYPE_MEMORY:
		ret = virtio_device_type_result_ok(VIRTIO_DEVICE_TYPE_MEMORY);
		break;
	default:
		ret = virtio_device_type_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
virtio_device_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VIRTIO_DEVICE_TYPE_INVALID:
	case (uint32_t)VIRTIO_DEVICE_TYPE_NETWORK:
	case (uint32_t)VIRTIO_DEVICE_TYPE_BLOCK:
	case (uint32_t)VIRTIO_DEVICE_TYPE_CONSOLE:
	case (uint32_t)VIRTIO_DEVICE_TYPE_BALLOON:
	case (uint32_t)VIRTIO_DEVICE_TYPE_GPU:
	case (uint32_t)VIRTIO_DEVICE_TYPE_INPUT:
	case (uint32_t)VIRTIO_DEVICE_TYPE_SOCKET:
	case (uint32_t)VIRTIO_DEVICE_TYPE_IOMMU:
	case (uint32_t)VIRTIO_DEVICE_TYPE_MEMORY:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

virtio_transport_type_t
virtio_transport_type_raw_cast(uint32_t val)
{
	virtio_transport_type_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_MMIO:
		ret = VIRTIO_TRANSPORT_TYPE_MMIO;
		break;
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_PCI:
		ret = VIRTIO_TRANSPORT_TYPE_PCI;
		break;
	default:
		// Invalid virtio_transport_type
		__builtin_trap();
	}
#else
	ret = (virtio_transport_type_t)val;
#endif

	return ret;
}

virtio_transport_type_result_t
virtio_transport_type_raw_cast_safe(uint32_t val)
{
	virtio_transport_type_result_t ret;

	switch (val) {
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_MMIO:
		ret = virtio_transport_type_result_ok(
			VIRTIO_TRANSPORT_TYPE_MMIO);
		break;
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_PCI:
		ret = virtio_transport_type_result_ok(
			VIRTIO_TRANSPORT_TYPE_PCI);
		break;
	default:
		ret = virtio_transport_type_result_error(
			ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
virtio_transport_type_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_MMIO:
	case (uint32_t)VIRTIO_TRANSPORT_TYPE_PCI:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

vpm_state_t
vpm_state_raw_cast(uint32_t val)
{
	vpm_state_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)VPM_STATE_NO_STATE:
		ret = VPM_STATE_NO_STATE;
		break;
	case (uint32_t)VPM_STATE_RUNNING:
		ret = VPM_STATE_RUNNING;
		break;
	case (uint32_t)VPM_STATE_CPUS_SUSPENDED:
		ret = VPM_STATE_CPUS_SUSPENDED;
		break;
	case (uint32_t)VPM_STATE_SYSTEM_SUSPENDED:
		ret = VPM_STATE_SYSTEM_SUSPENDED;
		break;
	default:
		// Invalid vpm_state
		__builtin_trap();
	}
#else
	ret = (vpm_state_t)val;
#endif

	return ret;
}

vpm_state_result_t
vpm_state_raw_cast_safe(uint32_t val)
{
	vpm_state_result_t ret;

	switch (val) {
	case (uint32_t)VPM_STATE_NO_STATE:
		ret = vpm_state_result_ok(VPM_STATE_NO_STATE);
		break;
	case (uint32_t)VPM_STATE_RUNNING:
		ret = vpm_state_result_ok(VPM_STATE_RUNNING);
		break;
	case (uint32_t)VPM_STATE_CPUS_SUSPENDED:
		ret = vpm_state_result_ok(VPM_STATE_CPUS_SUSPENDED);
		break;
	case (uint32_t)VPM_STATE_SYSTEM_SUSPENDED:
		ret = vpm_state_result_ok(VPM_STATE_SYSTEM_SUSPENDED);
		break;
	default:
		ret = vpm_state_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
vpm_state_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)VPM_STATE_NO_STATE:
	case (uint32_t)VPM_STATE_RUNNING:
	case (uint32_t)VPM_STATE_CPUS_SUSPENDED:
	case (uint32_t)VPM_STATE_SYSTEM_SUSPENDED:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}

watchdog_manage_op_t
watchdog_manage_op_raw_cast(uint32_t val)
{
	watchdog_manage_op_t ret;

#if !defined(NDEBUG)
	switch (val) {
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE:
		ret = WATCHDOG_MANAGE_OP_FREEZE;
		break;
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE_AND_RESET:
		ret = WATCHDOG_MANAGE_OP_FREEZE_AND_RESET;
		break;
	case (uint32_t)WATCHDOG_MANAGE_OP_UNFREEZE:
		ret = WATCHDOG_MANAGE_OP_UNFREEZE;
		break;
	default:
		// Invalid watchdog_manage_op
		__builtin_trap();
	}
#else
	ret = (watchdog_manage_op_t)val;
#endif

	return ret;
}

watchdog_manage_op_result_t
watchdog_manage_op_raw_cast_safe(uint32_t val)
{
	watchdog_manage_op_result_t ret;

	switch (val) {
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE:
		ret = watchdog_manage_op_result_ok(WATCHDOG_MANAGE_OP_FREEZE);
		break;
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE_AND_RESET:
		ret = watchdog_manage_op_result_ok(
			WATCHDOG_MANAGE_OP_FREEZE_AND_RESET);
		break;
	case (uint32_t)WATCHDOG_MANAGE_OP_UNFREEZE:
		ret = watchdog_manage_op_result_ok(WATCHDOG_MANAGE_OP_UNFREEZE);
		break;
	default:
		ret = watchdog_manage_op_result_error(ERROR_ARGUMENT_INVALID);
		break;
	}

	return ret;
}

bool
watchdog_manage_op_raw_is_valid(uint32_t val)
{
	bool ret;

	switch (val) {
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE:
	case (uint32_t)WATCHDOG_MANAGE_OP_FREEZE_AND_RESET:
	case (uint32_t)WATCHDOG_MANAGE_OP_UNFREEZE:
		ret = true;
		break;
	default:
		ret = false;
		break;
	}

	return ret;
}
