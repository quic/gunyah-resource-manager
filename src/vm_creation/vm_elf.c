// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <stdio.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <cache.h>
#include <elf.h>
#include <vm_elf.h>

rm_error_t
vm_elf_process_ptload_segments(Elf_Ehdr_ptr ehdr, Elf_Phdr_ptr phdrs,
			       uintptr_t mem_base, vmaddr_t mem_size,
			       paddr_t		      phys_base,
			       boot_env_phys_range_t *vm_segments,
			       size_t num_vm_segments, size_t *vm_segment_count,
			       paddr_t *entry_offset, paddr_t *dt_offset,
			       size_t *dt_size, bool *single_dtb)
{
	rm_error_t ret = RM_ERROR_MEM_INVALID;

	Elf_Class class = elf_get_ehdr_class(ehdr);
	if ((class != ELF_CLASS_32) && (class != ELF_CLASS_64)) {
		goto out;
	}

	count_t e_phnum = elf_get_ehdr_field(ehdr, e_phnum);

	// Flush the max header size (ELF64)
	cache_flush_by_va(phdrs.phdr64, sizeof(Elf64_Phdr) * e_phnum);

	// Check all the PT_LOAD segments.
	index_t segment_count = 0U;
	bool	relocatable   = false;
	for (index_t i = 0U; i < e_phnum; i++) {
		// Ignore non-loadable segments.
		if (!elf_segment_is_loadable(class, phdrs, i)) {
			continue;
		}

		// Find the segment address relative to the start of the parcel.
		// Segments marked relocatable are already loaded relative to
		// the start; otherwise they are loaded at their absolute
		// physical address (assuming the loading VM had it mapped 1:1
		// or else knew the real physical base; authentication of
		// absolute addressed images will fail otherwise).
		size_t segment_offset =
			elf_get_phdr_field(class, phdrs, i, p_paddr);

		// If there is at least one relocatable segment, we need
		// to tell TZ the offset, and also apply it to the entry
		// point.
		relocatable = elf_segment_is_relocatable(class, phdrs, i);
		if (!relocatable) {
			// Note: underflow of this subtraction will be
			// caught by the range check below
			segment_offset -= phys_base;
		}

		size_t p_memsz = elf_get_phdr_field(class, phdrs, i, p_memsz);
		if (!elf_valid_ptload_segment(i, p_memsz, segment_offset,
					      segment_count, vm_segments,
					      mem_size)) {
			goto out;
		}

		// Save the segment for use during VM init, mostly for locating
		// the Linux initrd. Note that segment numbers in the DT only
		// count PT_LOAD segments; they're not simple phdr indices.
		if (segment_count < num_vm_segments) {
			vm_segments[segment_count].base = segment_offset;
			vm_segments[segment_count].size = p_memsz;
			segment_count++;
		}

		// Check whether the segment contains the DT.
		uint32_t *first_word = (uint32_t *)(mem_base + segment_offset);
		cache_flush_by_va(first_word, sizeof(*first_word));
		if (elf_segment_contains_dt(first_word, single_dtb)) {
			*dt_offset = segment_offset;
			*dt_size =
				elf_get_phdr_field(class, phdrs, i, p_filesz);
		}
	}
	*vm_segment_count = segment_count;

	if (*dt_size == 0U) {
		(void)printf("Error: no DTB segment found\n");
		goto out;
	}

	*entry_offset = elf_get_ehdr_field(ehdr, e_entry);
	if (!relocatable) {
		*entry_offset -= phys_base;
	}

	ret = RM_OK;

out:
	return ret;
}
