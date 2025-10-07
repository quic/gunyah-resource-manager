// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#ifndef INCLUDE_VM_ELF_H_
#define INCLUDE_VM_ELF_H_

rm_error_t
vm_elf_process_ptload_segments(Elf_Ehdr_ptr ehdr, Elf_Phdr_ptr phdrs,
			       uintptr_t mem_base, vmaddr_t mem_size,
			       paddr_t		      phys_base,
			       boot_env_phys_range_t *vm_segments,
			       size_t num_vm_segments, size_t *vm_segment_count,
			       paddr_t *entry_offset, paddr_t *dt_offset,
			       size_t *dt_size, bool *single_dtb);

#else

#error multiple include of vm_elf.h

#endif
