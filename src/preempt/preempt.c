// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <asm/interrupt.h>

#include <preempt.h>

// FIXME:
static uint32_t preempt_disable_count;

void
preempt_disable(void)
{
	asm_interrupt_disable_acquire(&preempt_disable_count);
	preempt_disable_count++;
	assert_preempt_disabled();
}

void
preempt_enable(void)
{
	assert_preempt_disabled();
	preempt_disable_count--;
	if (preempt_disable_count == 0U) {
		asm_interrupt_enable_release(&preempt_disable_count);
	}
}

void
assert_preempt_disabled(void)
{
	assert(preempt_disable_count != 0U);
}

void
assert_preempt_enabled(void)
{
	assert(preempt_disable_count == 0U);
}
