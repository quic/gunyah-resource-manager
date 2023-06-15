// © 2021 Qualcomm Innovation Center, Inc. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

typedef uint16_t Elf_Half;
typedef uint32_t Elf_Word;
typedef int32_t	 Elf_Sword;

#if defined(USE_ELF64)

typedef int64_t	 Elf_Sxword;
typedef uint64_t Elf_Xword;
typedef uint64_t Elf_Addr;
typedef uint64_t Elf_Off;

#define ELF_CLASS ELF_CLASS_64

#elif defined(USE_ELF32)

typedef uint32_t Elf_Addr;
typedef uint32_t Elf_Off;

#define ELF_CLASS ELF_CLASS_32

#else
#error please define USE_ELF32 or USE_ELF64
#endif

#define EI_NIDENT 16

#define EI_MAG_STR                                                             \
	"\x7f"                                                                 \
	"ELF"
#define EI_MAG_SIZE 4

#define EI_CLASS      4
#define EI_DATA	      5
#define EI_VERSION    6
#define EI_OSABI      7
#define EI_ABIVERSION 8
#define EI_PAD	      9

#define ELF_CLASS_NONE 0
#define ELF_CLASS_32   1
#define ELF_CLASS_64   2

#define ELF_DATA_NONE 0
#define ELF_DATA_2LSB 1
#define ELF_DATA_2MSB 2

#define EV_NONE	   0
#define EV_CURRENT 1

#define ET_NONE 0
#define ET_REL	1
#define ET_EXEC 2
#define ET_DYN	3
#define ET_CORE 4

#define PT_NULL	   0
#define PT_LOAD	   1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE	   4
#define PT_SHLIB   5
#define PT_PHDR	   6
#define PT_TLS	   7
#define PT_NUM	   8

#define PF_X		    1
#define PF_W		    2
#define PF_R		    4
#define PF_QCOM_RELOCATABLE 0x08000000U

typedef struct {
	unsigned char e_ident[EI_NIDENT];

	Elf_Half e_type;
	Elf_Half e_machine;
	Elf_Word e_version;
	Elf_Addr e_entry;
	Elf_Off	 e_phoff;
	Elf_Off	 e_shoff;
	Elf_Word e_flags;

	Elf_Half e_ehsize;
	Elf_Half e_phentsize;
	Elf_Half e_phnum;
	Elf_Half e_shentsize;
	Elf_Half e_shnum;
	Elf_Half e_shstrndx;
} Elf_Ehdr;

typedef struct {
#if defined(USE_ELF64)
	Elf_Word  p_type;
	Elf_Word  p_flags;
	Elf_Off	  p_offset;
	Elf_Addr  p_vaddr;
	Elf_Addr  p_paddr;
	Elf_Xword p_filesz;
	Elf_Xword p_memsz;
	Elf_Xword p_align;
#else
	Elf_Word p_type;
	Elf_Off	 p_offset;
	Elf_Addr p_vaddr;
	Elf_Addr p_paddr;
	Elf_Word p_filesz;
	Elf_Word p_memsz;
	Elf_Word p_flags;
	Elf_Word p_align;
#endif
} Elf_Phdr;
