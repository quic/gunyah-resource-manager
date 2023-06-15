// © 2022 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>

#include <util.h>

#include <cache.h>

static uint64_t
read_ctr(void)
{
	uint64_t ctr_el0;

	// Read the Cache Type Register.
	__asm__("mrs  %0, ctr_el0\n" : "=r"(ctr_el0));

	return ctr_el0;
}

void
cache_clean_by_va(void *ptr, size_t size)
{
	uint64_t      ctr_el0	   = read_ctr();
	const count_t line_size_p2 = (count_t)((ctr_el0 >> 16U) & 0xfU);
	const bool    dic	   = ((ctr_el0 & util_bit(29U)) != 0U);

	uintptr_t aligned_va = util_p2align_down((uintptr_t)ptr, line_size_p2);
	uintptr_t end	     = (uintptr_t)ptr + size - 1U;

	// No barrier is needed before the CMOs, because we are cleaning writes
	// made through the same mapping.

	const size_t line_size = util_bit(line_size_p2);
	for (uintptr_t addr = aligned_va; addr <= end; addr += line_size) {
		// Clean one cache line by VA to the point of coherency.
		__asm__ volatile("dc  cvac, %0\n" : : "r"(addr) : "memory");
	}

	// A DSB is needed to synchronise any future reads by instruction
	// accesses. The implied DMB is also needed to synchronise any future
	// reads by data accesses with different cache attributes.
	__asm__ volatile("dsb ish" ::: "memory");

	if (!dic) {
		// This CPU requires explicit instruction cache maintenance.
		// Invalidate all instruction caches, and execute another DSB
		// to ensure that future reads by instruction accesses are
		// ordered after completion of the invalidate.
		__asm__ volatile("ic ialluis" ::: "memory");
		__asm__ volatile("dsb ish" ::: "memory");
	}
}

void
cache_flush_by_va(void *ptr, size_t size)
{
	uint64_t      ctr_el0	   = read_ctr();
	const count_t line_size_p2 = (count_t)((ctr_el0 >> 16U) & 0xfU);

	uintptr_t aligned_va = util_p2align_down((uintptr_t)ptr, line_size_p2);
	uintptr_t end	     = (uintptr_t)ptr + size - 1U;

	// A DMB is needed to synchronise any earlier writes to the range that
	// were made with different cache attributes.
	__asm__ volatile("dmb ish" ::: "memory");

	const size_t line_size = util_bit(line_size_p2);
	for (uintptr_t addr = aligned_va; addr <= end; addr += line_size) {
		// Clean and invalidate one cache line by VA to the point of
		// coherency.
		__asm__ volatile("dc  civac, %0\n" : : "r"(addr) : "memory");
	}

	// No barrier is needed after the CMOs, because we are flushing lines to
	// be accessed by RM through the same mapping.
}
