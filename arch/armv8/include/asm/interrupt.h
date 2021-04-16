// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Enable all interrupts, with a compiler release fence.
#define asm_interrupt_enable_release(flag_ptr)                                 \
	do {                                                                   \
		atomic_signal_fence(memory_order_release);                     \
		__asm__ volatile("msr daifclr, 0x7" : "+m"(*(flag_ptr)));      \
	} while ((_Bool)0)

// Disable all interrupts, with a compiler acquire fence.
#define asm_interrupt_disable_acquire(flag_ptr)                                \
	do {                                                                   \
		__asm__ volatile("msr daifset, 0x7" ::"m"(*(flag_ptr)));       \
		atomic_signal_fence(memory_order_acquire);                     \
	} while ((_Bool)0)
