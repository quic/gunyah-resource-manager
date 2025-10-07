// © 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_VM_MGNT_ARCH_H_
#define ARCH_ARMv8_VM_MGNT_ARCH_H_

// Set cleanup type for a VM
void
vm_mgnt_arch_set_cleanup_type(vm_t *vm, const uint32_t *extra_reason);

#else

#error arch/armv8/include/vm_mgnt_arch.h multiple include

#endif
