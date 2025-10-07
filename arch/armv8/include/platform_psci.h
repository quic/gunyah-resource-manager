// © 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_PLATFORM_PSCI_H_
#define ARCH_ARMv8_PLATFORM_PSCI_H_

// Get cleanup type for a VM
bool
platform_psci_get_vm_clean_shutdown(uint32_t reset_type, uint64_t cookie);

#else

#error arch/armv8/include/platform_psci.h multiple include

#endif
