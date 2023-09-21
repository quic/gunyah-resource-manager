// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

bool
arch_irq_cpulocal_valid(uint32_t irq);
bool
arch_irq_global_valid(uint32_t irq);

uint32_t
arch_irq_cpulocal_max(void);
uint32_t
arch_irq_global_max(void);

// Return the next valid irq number, starting from the provided input.
//
// The provided input must be an invalid global irq number.
//
// Returns 0 on failure.
uint32_t
arch_irq_cpulocal_next_valid(uint32_t irq);
uint32_t
arch_irq_global_next_valid(uint32_t irq);
