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
	return ((irq >= 16U) && (irq <= 31U)) ||
	       ((irq >= 1056U) && (irq <= 1119U));
}

bool
arch_irq_global_valid(uint32_t irq)
{
	return ((irq >= 32U) && (irq <= 1019U)) ||
	       ((irq >= 4096U) && (irq <= 5119U));
}

uint32_t
arch_irq_cpulocal_max(void)
{
	return 1119U;
}

uint32_t
arch_irq_global_max(void)
{
	return 5119U;
}

uint32_t
arch_irq_cpulocal_next_valid(uint32_t irq)
{
	uint32_t next;

	assert(!arch_irq_cpulocal_valid(irq));

	if (irq < 16U) {
		next = 16U;
	} else if (irq < 1056U) {
		next = 1056U;
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

	if (irq < 32U) {
		next = 32U;
	} else if (irq < 4096U) {
		next = 4096U;
	} else {
		next = 0U; // Failure
	}
	return next;
}
