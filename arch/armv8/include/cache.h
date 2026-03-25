// Copyright © Qualcomm Technologies, Inc. and/or its subsidiaries.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ARCH_ARMv8_CACHE_H_
#define ARCH_ARMv8_CACHE_H_

// Ensure that any writes by RM through the specified pointer that lie in the
// specified memory range have been written back to main memory and are visible
// to all data and instruction accesses made by VMs with any cache attribute.
// This is typically used after zeroing memory to sanitise it, or after copying
// code into memory for access by a VM.
void
cache_clean_by_va(const void *va, size_t size);

// Ensure that all data accesses to the specified memory range by any VM with
// any cache attribute are visible to accesses by RM through the specified
// pointer. This is typically used before accessing data provided by another VM.
void
cache_flush_by_va(const void *va, size_t size);

// Invalidate all of the instruction cache so it is coherent with any previous
// data cache clean or flush.
void
cache_invalidate_inst_all(void);

#else

#error arch/armv8/include/cache.h multiple include

#endif
