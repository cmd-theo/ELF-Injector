#pragma once
#include <bfd.h>
#include <stdbool.h>
#include "elf64_types.h"
int find_arch(bfd *current);
char *find_bin_format(bfd *current);
bool is_executable(flagword flag);
int elf_header_parser(Elf64_Ehdr *res, char *file);
int find_pt_note(Elf64_Ehdr *res, char *file, int *index);
int inject_code(char *file, char *bin, char *modified);
int find_index_section(Elf64_Ehdr *elf_header, Elf64_Shdr *section_header, char *file);
int modify_section(Elf64_Ehdr *elf_header, Elf64_Shdr *section_header, int index, int binsize, char *file, Elf64_Addr new_addr, Elf64_Off new_offset);
int reorder_section_hdr(Elf64_Ehdr *elf_header, char *file, int indexsh);
int modify_name_section(Elf64_Ehdr *elf_header, char *file, char *name, int name_size);
int modify_pt_note(Elf64_Ehdr *res, Elf64_Shdr *section_header, char *file, int index);
int modify_entrypoint(Elf64_Ehdr *ehdr, int new_address, char *file);
int bin_size(char *bin);
int got_hijack(Elf64_Ehdr *elf_header, Elf64_Shdr *section_header, char *file, uint64_t base_address);