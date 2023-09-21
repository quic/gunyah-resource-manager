// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <irq_arch.h>

bool
arch_irq_cpulocal_valid(uint32_t irq)
{
	// TODO: support extended PPIs
	return (irq >= 16U) && (irq <= 31U);
}

bool
arch_irq_global_valid(uint32_t irq)
{
	// TODO: support extended SPIs
	return (irq >= 32U) && (irq <= 1019U);
}

uint32_t
arch_irq_cpulocal_max(void)
{
	// TODO: support extended PPIs
	return 31U;
}

uint32_t
arch_irq_global_max(void)
{
	// TODO: support extended SPIs
	return 1019U;
}

uint32_t
arch_irq_cpulocal_next_valid(uint32_t irq)
{
	uint32_t next;

	assert(!arch_irq_cpulocal_valid(irq));

	// TODO: support extended PPIs
	if (irq < 16U) {
		next = 16U;
	} else {
		next = 0U; // Failure
	}
	return next;
}

uint32_t
arch_irq_global_next_valid(uint32_t irq)
{
	uint32_t next;

	assert(!arch_irq_global_valid(irq));

	// TODO: support extended SPIs
	if (irq < 32U) {
		next = 32U;
	} else {
		next = 0U; // Failure
	}
	return next;
}
