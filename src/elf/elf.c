// © 2023 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

#include <guest_types.h>

#include <assert.h>
#include <endian.h>
#include <stdio.h>
#include <string.h>

#include <rm_types.h>
#include <util.h>

#include <cache.h>
#include <elf.h>

#define DT_TABLE_MAGIC betoh32(0xd7b7ab1eU)
#define DT_MAGIC       betoh32(0xd00dfeedU)

Elf_Class
elf_get_ehdr_class(Elf_Ehdr_ptr ehdr)
{
	assert(ehdr.ehdr32 != NULL);

	return ehdr.ehdr32->e_ident[EI_CLASS];
}

size_t
elf_ehdr_size(Elf_Ehdr_ptr ehdr)
{
	return (elf_get_ehdr_class(ehdr) == ELF_CLASS_32) ? sizeof(Elf32_Ehdr)
							  : sizeof(Elf64_Ehdr);
}

static size_t
elf_get_phdr_size(Elf_Ehdr_ptr ehdr)
{
	return (elf_get_ehdr_class(ehdr) == ELF_CLASS_32) ? sizeof(Elf32_Phdr)
							  : sizeof(Elf64_Phdr);
}

bool
elf_ehdr_is_class(Elf_Ehdr_ptr ehdr, Elf_Class class)
{
	return (elf_get_ehdr_class(ehdr) == class);
}

bool
elf_ehdr_valid(Elf_Ehdr_ptr ehdr)
{
	bool valid = false;

	// Flush the max header size (ELF64)
	cache_flush_by_va(ehdr.ehdr64, sizeof(Elf64_Ehdr));

	// Validate the ELF image
	if ((memcmp((const Elf_Ident *)EI_MAG_STR,
		    elf_get_ehdr_field(ehdr, e_ident), EI_MAG_SIZE) == 0) &&
	    (elf_ehdr_is_class(ehdr, ELF_CLASS_32) ||
	     elf_ehdr_is_class(ehdr, ELF_CLASS_64)) &&
	    (elf_get_ehdr_field(ehdr, e_ident[EI_DATA]) == ELF_DATA_2LSB) &&
	    (elf_get_ehdr_field(ehdr, e_ident[EI_VERSION]) == EV_CURRENT) &&
	    (elf_get_ehdr_field(ehdr, e_ident[EI_OSABI]) == 0U) &&
	    (elf_get_ehdr_field(ehdr, e_ident[EI_ABIVERSION]) == 0U) &&
	    (elf_get_ehdr_field(ehdr, e_phentsize) ==
	     elf_get_phdr_size(ehdr))) {
		valid = true;
	} else {
		(void)printf("Error: unexpected value in ehdr\n");
	}

	return valid;
}

rm_error_t
elf_get_phdr_offset(Elf_Ehdr_ptr ehdr, size_t image_size, size_t *offset)
{
	rm_error_t rm_err = RM_ERROR_ARGUMENT_INVALID;

	size_t	e_phoff	    = elf_get_ehdr_field(ehdr, e_phoff);
	size_t	e_phentsize = elf_get_ehdr_field(ehdr, e_phentsize);
	count_t e_phnum	    = elf_get_ehdr_field(ehdr, e_phnum);

	// The e_phoff field is relative to the ehdr. We require that the phdrs
	// are copied along with the ehdr as a single block. A real ELF file is
	// not guaranteed to have them close together, so the loader may need to
	// move the phdrs closer and adjust e_phoff.
	if (util_mult_integer_overflows(e_phentsize, e_phnum) ||
	    util_add_overflows(e_phoff, e_phentsize * e_phnum) ||
	    (image_size < (e_phoff + (e_phentsize * e_phnum)))) {
		(void)printf("Error: phdr size or location is out of range\n");
	} else {
		*offset = e_phoff;
		rm_err	= RM_OK;
	}

	return rm_err;
}

bool
elf_segment_is_loadable(Elf_Class class, Elf_Phdr_ptr phdrs, index_t seg_num)
{
	return elf_get_phdr_field(class, phdrs, seg_num, p_type) == PT_LOAD;
}

bool
elf_segment_is_relocatable(Elf_Class class, Elf_Phdr_ptr phdrs, index_t seg_num)
{
	return (elf_get_phdr_field(class, phdrs, seg_num, p_flags) &
		PF_QCOM_RELOCATABLE) != 0U;
}

bool
elf_valid_ptload_segment(index_t seg_num, size_t p_memsz, size_t segment_offset,
			 index_t		      segment_count,
			 const boot_env_phys_range_t *vm_segments,
			 vmaddr_t		      mem_size)
{
	bool valid = false;

	// Check that the segment is within the image memparcel.
	if (util_add_overflows(p_memsz, segment_offset) ||
	    ((p_memsz + segment_offset) > mem_size)) {
		(void)printf("Error: phdr %d is outside image memparcel\n",
			     seg_num);
		goto out;
	}

	// Check for overlapping segments
	for (index_t s = 0; s < segment_count; s++) {
		paddr_t s_base = vm_segments[s].base;
		size_t	s_size = vm_segments[s].size;
		if (((segment_offset < s_base) &&
		     ((segment_offset + p_memsz) > s_base)) ||
		    ((segment_offset >= s_base) &&
		     (segment_offset < (s_base + s_size)))) {
			(void)printf("Error: phdr %d is overlapping phdr %d\n",
				     seg_num, s);
			goto out;
		}
	}

	valid = true;

out:
	return valid;
}

bool
elf_segment_contains_dt(const uint32_t *first_word, bool *single_dtb)
{
	bool found = false;

	if (*first_word == DT_TABLE_MAGIC) {
		*single_dtb = false;
		found	    = true;
	} else if (*first_word == DT_MAGIC) {
		*single_dtb = true;
		found	    = true;
	} else {
		// no DTB segment found
	}

	return found;
}
