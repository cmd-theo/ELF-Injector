#pragma once
#include <stdint.h>
#include <stdio.h>

#define PT_NOTE_TYPE 4
#define PH_HEADER_ALIGNMENT 16
#define FIELD_TYPE 14
#define SHT_PROGBITS 0x1
#define SHF_EXECINST 0x4
#define PT_LOAD 1
#define PF_X 0x1
#define PF_R 0x4
#define GET_ENV_OFFSET 40
typedef uint64_t Elf64_Addr;
typedef uint16_t Elf64_Half;
typedef uint64_t Elf64_Off;
typedef int32_t Elf64_Sword;
typedef int64_t Elf64_Sxword;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Lword;
typedef uint64_t Elf64_Xword;

typedef struct
{
    unsigned char e_ident[16]; /* File identification. */
    Elf64_Half e_type;                /* File type. */
    Elf64_Half e_machine;             /* Machine architecture. */
    Elf64_Word e_version;             /* ELF format version. */
    Elf64_Addr e_entry;               /* Entry point. */
    Elf64_Off e_phoff;                /* Program header file offset. */
    Elf64_Off e_shoff;                /* Section header file offset. */
    Elf64_Word e_flags;               /* Architecture-specific flags. */
    Elf64_Half e_ehsize;              /* Size of ELF header in bytes. */
    Elf64_Half e_phentsize;           /* Size of program header entry. */
    Elf64_Half e_phnum;               /* Number of program header entries. */
    Elf64_Half e_shentsize;           /* Size of section header entry. */
    Elf64_Half e_shnum;               /* Number of section header entries. */
    Elf64_Half e_shstrndx;            /* Section name strings section. */
} Elf64_Ehdr;

typedef struct
{
    Elf64_Word sh_name;       /* Section name (index into the section header string table). */
    Elf64_Word sh_type;       /* Section type. */
    Elf64_Xword sh_flags;     /* Section flags. */
    Elf64_Addr sh_addr;       /* Address in memory image. */
    Elf64_Off sh_offset;      /* Offset in file. */
    Elf64_Xword sh_size;      /* Size in bytes. */
    Elf64_Word sh_link;       /* Index of a related section. */
    Elf64_Word sh_info;       /* Depends on section type. */
    Elf64_Xword sh_addralign; /* Alignment in bytes. */
    Elf64_Xword sh_entsize;   /* Size of each entry in section. */
} Elf64_Shdr;

typedef struct
{
    Elf64_Word p_type;    /* Entry type. */
    Elf64_Word p_flags;   /* Access permission flags. */
    Elf64_Off p_offset;   /* File offset of contents. */
    Elf64_Addr p_vaddr;   /* Virtual address in memory image. */
    Elf64_Addr p_paddr;   /* Physical address (not used). */
    Elf64_Xword p_filesz; /* Size of contents in file. */
    Elf64_Xword p_memsz;  /* Size of contents in memory. */
    Elf64_Xword p_align;  /* Alignment in memory and file. */
} Elf64_Phdr;