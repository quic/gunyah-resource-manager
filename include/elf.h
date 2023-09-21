// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef uint16_t Elf_Half;
typedef uint32_t Elf_Word;
typedef int32_t	 Elf_Sword;
typedef int64_t	 Elf_Sxword;
typedef uint64_t Elf_Xword;

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

typedef unsigned      Elf_Class;
typedef unsigned char Elf_Ident;

#define EI_NIDENT 16U

#define EI_MAG_STR                                                             \
	"\x7f"                                                                 \
	"ELF"
#define EI_MAG_SIZE 4U

#define EI_CLASS      4U
#define EI_DATA	      5U
#define EI_VERSION    6U
#define EI_OSABI      7U
#define EI_ABIVERSION 8U
#define EI_PAD	      9U

#define ELF_CLASS_NONE 0U
#define ELF_CLASS_32   1U
#define ELF_CLASS_64   2U

#define ELF_DATA_NONE 0U
#define ELF_DATA_2LSB 1U
#define ELF_DATA_2MSB 2U

#define EV_NONE	   0U
#define EV_CURRENT 1U

#define ET_NONE 0U
#define ET_REL	1U
#define ET_EXEC 2U
#define ET_DYN	3U
#define ET_CORE 4U

#define PT_NULL	   0U
#define PT_LOAD	   1U
#define PT_DYNAMIC 2U
#define PT_INTERP  3U
#define PT_NOTE	   4U
#define PT_SHLIB   5U
#define PT_PHDR	   6U
#define PT_TLS	   7U
#define PT_NUM	   8U

#define PF_X		    1U
#define PF_W		    2U
#define PF_R		    4U
#define PF_QCOM_RELOCATABLE 0x08000000U

typedef struct {
	Elf_Ident e_ident[EI_NIDENT];

	Elf_Half   e_type;
	Elf_Half   e_machine;
	Elf_Word   e_version;
	Elf32_Addr e_entry;
	Elf32_Off  e_phoff;
	Elf32_Off  e_shoff;
	Elf_Word   e_flags;

	Elf_Half e_ehsize;
	Elf_Half e_phentsize;
	Elf_Half e_phnum;
	Elf_Half e_shentsize;
	Elf_Half e_shnum;
	Elf_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
	Elf_Word   p_type;
	Elf32_Off  p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf_Word   p_filesz;
	Elf_Word   p_memsz;
	Elf_Word   p_flags;
	Elf_Word   p_align;
} Elf32_Phdr;

typedef struct {
	Elf_Ident e_ident[EI_NIDENT];

	Elf_Half   e_type;
	Elf_Half   e_machine;
	Elf_Word   e_version;
	Elf64_Addr e_entry;
	Elf64_Off  e_phoff;
	Elf64_Off  e_shoff;
	Elf_Word   e_flags;

	Elf_Half e_ehsize;
	Elf_Half e_phentsize;
	Elf_Half e_phnum;
	Elf_Half e_shentsize;
	Elf_Half e_shnum;
	Elf_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
	Elf_Word   p_type;
	Elf_Word   p_flags;
	Elf64_Off  p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf_Xword  p_filesz;
	Elf_Xword  p_memsz;
	Elf_Xword  p_align;
} Elf64_Phdr;

typedef union {
	Elf32_Ehdr *ehdr32;
	Elf64_Ehdr *ehdr64;
} Elf_Ehdr_ptr;

typedef union {
	Elf32_Phdr *phdr32;
	Elf64_Phdr *phdr64;
} Elf_Phdr_ptr;

// These macros assume the pointer is valid and CLASS has been checked as
// supported.
#define elf_get_ehdr_field(ehdr, field)                                        \
	((elf_get_ehdr_class(ehdr) == ELF_CLASS_32) ? ((ehdr).ehdr32->field)   \
						    : ((ehdr).ehdr64->field))

#define elf_get_phdr_field(class, phdr, i, field)                              \
	(((class) == ELF_CLASS_32) ? ((phdr).phdr32[(i)].field)                \
				   : ((phdr).phdr64[(i)].field))

Elf_Class
elf_get_ehdr_class(Elf_Ehdr_ptr ehdr);

size_t
elf_ehdr_size(Elf_Ehdr_ptr ehdr);

bool
elf_ehdr_valid(Elf_Ehdr_ptr ehdr);

bool
elf_ehdr_is_class(Elf_Ehdr_ptr ehdr, Elf_Class class);

rm_error_t
elf_get_phdr_offset(Elf_Ehdr_ptr ehdr, size_t image_size, size_t *e_phoff);

bool
elf_segment_is_loadable(Elf_Class class, Elf_Phdr_ptr phdrs, index_t seg_num);

bool
elf_segment_is_relocatable(Elf_Class class, Elf_Phdr_ptr phdrs,
			   index_t seg_num);

bool
elf_valid_ptload_segment(index_t seg_num, size_t p_memsz, size_t segment_offset,
			 index_t		      segment_count,
			 const boot_env_phys_range_t *vm_segments,
			 vmaddr_t		      mem_size);

bool
elf_segment_contains_dt(const uint32_t *first_word, bool *single_dtb);
