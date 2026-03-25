// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_VM_FIRMWARE_ARCH_H_
#define ARCH_ARMv8_VM_FIRMWARE_ARCH_H_

typedef enum arch_register_set_e {
	ARCH_REG_SET_X	= 0,
	ARCH_REG_SET_PC = 1,
	ARCH_REG_SET_SP = 2,
} arch_register_set_t;

#define BOOT_CONTEXT_GENERAL_REGS 31U

struct vm_boot_context_s {
	uint64_t x[BOOT_CONTEXT_GENERAL_REGS];
	uint64_t pc;
	uint64_t sp_el[2];
};

#else

#error arch/armv8/include/vm_firmware_arch.h multiple include

#endif
