#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <argp.h>
#include <bfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include "../include/elf64_types.h"

int find_arch(bfd *current)
{
	return bfd_get_arch_size(current);
}

bool is_executable(flagword flags)
{
	return ((flags & 0x2) != 0);
}

char *find_bin_format(bfd *current)
{
	char *res;
	switch (bfd_get_flavour(current))
	{
	case bfd_target_unknown_flavour:
		res = "unknown file format";
		break;
	case bfd_target_aout_flavour:
		res = "aout file format file format";
		break;
	case bfd_target_coff_flavour:
		res = "coff file format file format";
		break;
	case bfd_target_ecoff_flavour:
		res = "ecoff file format";
		break;
	case bfd_target_xcoff_flavour:
		res = "xcoff file format";
		break;
	case bfd_target_elf_flavour:
		res = "elf file format";
		break;
	case bfd_target_tekhex_flavour:
		res = "tekhex file format";
		break;
	case bfd_target_srec_flavour:
		res = "srec file format";
		break;
	case bfd_target_verilog_flavour:
		res = "verilog file format";
		break;
	case bfd_target_ihex_flavour:
		res = "ihex file format";
		break;
	case bfd_target_som_flavour:
		res = "som file format";
		break;
	case bfd_target_os9k_flavour:
		res = "os9k file format";
		break;
	case bfd_target_versados_flavour:
		res = "versados file format";
		break;
	case bfd_target_msdos_flavour:
		res = "msdos file format";
		break;
	case bfd_target_ovax_flavour:
		res = "ovax file format";
		break;
	case bfd_target_evax_flavour:
		res = "evax file format";
		break;
	case bfd_target_mmo_flavour:
		res = "mmo file format";
		break;
	case bfd_target_mach_o_flavour:
		res = "mach_o file format";
		break;
	case bfd_target_pef_flavour:
		res = "peffile format";
		break;
	case bfd_target_pef_xlib_flavour:
		res = "xlib file format";
		break;
	case bfd_target_sym_flavour:
		res = "sym file format";
		break;
	default:
		res = "Unknown format";
	}
	return res;
}

void fill_ehdr(Elf64_Ehdr *res, Elf64_Ehdr *temp)
{
	for (int i = 0; i < 16; i++)
	{
		res->e_ident[i] = temp->e_ident[i];
	}
	res->e_type = temp->e_type;
	res->e_machine = temp->e_machine;
	res->e_version = temp->e_version;
	res->e_entry = temp->e_entry;
	res->e_phoff = temp->e_phoff;
	res->e_shoff = temp->e_shoff;
	res->e_flags = temp->e_flags;
	res->e_ehsize = temp->e_ehsize;
	res->e_phentsize = temp->e_phentsize;
	res->e_phnum = temp->e_phnum;
	res->e_shentsize = temp->e_shentsize;
	res->e_shnum = temp->e_shnum;
	res->e_shstrndx = temp->e_shstrndx;
}

void fill_shdr(Elf64_Shdr *res, Elf64_Shdr *temp)
{
	res->sh_addr = temp->sh_addr;
	res->sh_addralign = temp->sh_addralign;
	res->sh_entsize = temp->sh_entsize;
	res->sh_flags = temp->sh_flags;
	res->sh_info = temp->sh_info;
	res->sh_link = temp->sh_link;
	res->sh_name = temp->sh_name;
	res->sh_offset = temp->sh_offset;
	res->sh_size = temp->sh_size;
	res->sh_type = temp->sh_type;
}

/* Parse the ELF header and put it in *res pointer */
int elf_header_parser(Elf64_Ehdr *res, char *file)
{
	Elf64_Ehdr *temp;
	int fd = -1;
	int status = -1;
	fd = open(file, O_RDONLY);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}

	temp = mmap(NULL, 64, PROT_READ, MAP_PRIVATE, fd, 0);
	fill_ehdr(res, temp);
	if (temp == MAP_FAILED)
	{
		status = -1;
		goto cleanup;
	}

	status = 0;
cleanup:
	fd = close(fd);
	munmap(temp, 64);

	return status;
}

int find_pt_note(Elf64_Ehdr *res, char *file, int *index)
{
	int fd = -1;
	int status = -1;
	fd = open(file, O_RDONLY);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	int p_header_size = (res->e_phnum * res->e_phentsize);
	uint32_t *elf_file_32 = mmap(NULL, 64 + p_header_size,
								 PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf_file_32 == MAP_FAILED)
	{
		goto cleanup;
	}
	for (int i = 0; i < res->e_phnum; i++)
	{
		uint32_t type = elf_file_32[PH_HEADER_ALIGNMENT + (i * FIELD_TYPE)];
		if (type == PT_NOTE_TYPE)
		{
			*index = i + 1;
			status = 0;
			break;
		}
	}

cleanup:
	fd = close(fd);
	munmap(elf_file_32, 64 + p_header_size);
	return status;
}

/* Inject the assembly code in the ELF file, inject the original entry point if
   the parameter MODIFIED is true. Return the offset of the injected code */
long inject_code(char *file, char *bin, char *modified)
{
	long offset = 0;
	int fd = -1;
	int fbin = -1;
	long bin_size = 0;
	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	fbin = open(bin, O_RDWR);
	if (fbin < 0)
	{
		fbin = close(fbin);
		return -1;
	}
	offset = lseek(fd, 0, SEEK_END);
	bin_size = lseek(fbin, 0, SEEK_END);
	char buffer[bin_size];
	lseek(fbin, 0, SEEK_SET);

	if (read(fbin, buffer, bin_size) == -1)
	{
		fbin = close(fbin);
		fd = close(fd);
		return -1;
	}
	if (write(fd, buffer, bin_size) == -1)
	{
		fbin = close(fbin);
		fd = close(fd);
		return -1;
	}

	if (strcmp("true", modified) == 0)
	{
		lseek(fd, -1, SEEK_END);
		if (write(fd, "\x68\xe0\x22\x40\x00\x5b\xff\xe3", 8) == -1)
		{
			fbin = close(fbin);
			fd = close(fd);
			return -1;
		}
	}
	fd = close(fd);
	fbin = close(fbin);
	return offset;
}

/* Find the index in the shstrtab of .not.ABI-tag section */
int find_index_section(Elf64_Ehdr *elf_header,
					   Elf64_Shdr *section_header, char *file)
{
	Elf64_Shdr *temp;
	int filesize = elf_header->e_shoff + (elf_header->e_shentsize *
										  elf_header->e_shnum);
	int fd = -1;
	int res = -1;
	int i = 0;
	fd = open(file, O_RDONLY);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	uint8_t *elf_file = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf_file == MAP_FAILED)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}
	temp = (void *)&elf_file[elf_header->e_shoff + (elf_header->e_shstrndx *
													elf_header->e_shentsize)];
	int shstrtab_offset = temp->sh_offset;
	int shstrtab_size = temp->sh_size;
	char buffer[shstrtab_size];

	while (i < elf_header->e_shnum)
	{
		temp = (void *)&elf_file[elf_header->e_shoff + (i * elf_header->e_shentsize)];
		int string_table_offset = shstrtab_offset + temp->sh_name;
		snprintf(buffer, shstrtab_size, "%s", &elf_file[string_table_offset]);

		if (strcmp(buffer, ".note.ABI-tag") == 0)
		{
			fill_shdr(section_header, temp);
			res = i;
			break;
		}
		i++;
	}

	fd = close(fd);
	munmap(elf_file, filesize);
	return res;
}

int bin_size(char *bin)
{
	int fbin = -1;
	int ret = 0;
	fbin = open(bin, O_RDWR);
	if (fbin < 0)
	{
		fbin = close(fbin);
		return -1;
	}
	ret = lseek(fbin, 0, SEEK_END);
	return ret + 8;
}

/* Modify the current section header in order to make it executable with the
   good parameters such as the address, the offset etc..*/
int modify_section(Elf64_Ehdr *elf_header, Elf64_Shdr *section_header, int index,
				   int binsize, char *file, Elf64_Addr new_addr, Elf64_Off new_offset)
{
	int fd = -1;
	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	section_header->sh_type = SHT_PROGBITS;
	section_header->sh_addr = new_addr;
	section_header->sh_offset = new_offset;
	section_header->sh_size = binsize;
	section_header->sh_addralign = 16; // 16 bytes alignment
	section_header->sh_flags |= SHF_EXECINST;
	lseek(fd, elf_header->e_shoff + (index * elf_header->e_shentsize), SEEK_SET);
	if (write(fd, section_header, elf_header->e_shentsize) == -1)
	{
		fd = close(fd);
		return -1;
	}
	fd = close(fd);
	return 0;
}

void exchange(Elf64_Shdr *s1, Elf64_Shdr *s2)
{
	Elf64_Shdr *temp = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr));
	if (temp == NULL)
	{
		return;
	}
	fill_shdr(temp, s1);
	fill_shdr(s1, s2);
	fill_shdr(s2, temp);
	free(temp);
}

/* Sort the section header array depending of their address */
void sort(Elf64_Shdr tab[], int indexsh, size_t size)
{
	int dyn_sym = tab[5].sh_name;
	int dyn_str = tab[6].sh_name;
	int dynsym_index = 0;
	int dynstr_index = 0;
	exchange(&tab[1], &tab[indexsh]); // first index of the tab is the modified hdr
	for (int i = 1; i < size - 3; i++)
	{
		if (tab[i].sh_addr > tab[i + 1].sh_addr)
		{
			exchange(&tab[i], &tab[i + 1]);
		}
	}
	//recover the new index
	for (int i = 0; i < size; i++)
	{
		if (tab[i].sh_name == dyn_str)
		{
			dynstr_index = i;
		}
		if (tab[i].sh_name == dyn_sym)
		{
			dynsym_index = i;
		}
	}
	//replace the sh_link to avoid warnings
	for (int i = 0; i < size; i++)
	{

		if (tab[i].sh_link != 0)
		{
			if (tab[i].sh_link == 5)
			{
				tab[i].sh_link = dynsym_index;
			}
			if (tab[i].sh_link == 6)
			{
				tab[i].sh_link = dynstr_index;
			}
		}
	}
}

/* Map the ELF file in the memory, store all the sections header of the file in
	an array, sort the sections headers according to their address */
int reorder_section_hdr(Elf64_Ehdr *elf_header, char *file, int indexsh)
{
	Elf64_Shdr *current_shdr;
	Elf64_Shdr tab[elf_header->e_shnum];
	int filesize = elf_header->e_shoff + (elf_header->e_shentsize *
										  elf_header->e_shnum);
	int fd = -1;
	int i = 0;
	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	uint8_t *elf_file = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf_file == MAP_FAILED)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}

	while (i < elf_header->e_shnum)
	{
		current_shdr = (void *)&elf_file[elf_header->e_shoff +
										 (i * elf_header->e_shentsize)];

		fill_shdr(&tab[i], current_shdr);
		i++;
	}

	sort(tab, indexsh, elf_header->e_shnum);
	i = 1;

	while (i < elf_header->e_shnum)
	{
		lseek(fd, elf_header->e_shoff + (i * elf_header->e_shentsize), SEEK_SET);
		if (write(fd, &tab[i], elf_header->e_shentsize) == -1)
		{
			fd = close(fd);
			munmap(elf_file, filesize);
			return -1;
		}
		i++;
	}

	fd = close(fd);
	munmap(elf_file, filesize);
	return 0;
}

/* Format the buffer to add or truncate characters according to the original
 section header name (.not.ABI-tag)*/
void format_buffer(char *buffer, char *name)
{
	int size_name = strlen(name);
	int size_notabi = strlen(".note.ABI-tag");
	if (size_name < size_notabi)
	{
		for (int i = 0; i < size_notabi; i++)
		{
			if (i < size_name)
				buffer[i] = name[i];
			if (i >= size_name)
				buffer[i] = ' ';
		}
	}
	if (size_name >= size_notabi)
	{
		for (int i = 0; i < size_notabi; i++)
		{
			buffer[i] = name[i];
		}
	}
}

/* Modify the name of the section .not.ABI-tag */
int modify_name_section(Elf64_Ehdr *elf_header,
						char *file, char *name, int name_size)
{
	Elf64_Shdr *temp;
	int filesize = elf_header->e_shoff + (elf_header->e_shentsize *
										  elf_header->e_shnum);
	int fd = -1;
	int res = -1;
	int i = 0;
	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	uint8_t *elf_file = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf_file == MAP_FAILED)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}
	temp = (void *)&elf_file[elf_header->e_shoff + (elf_header->e_shstrndx *
													elf_header->e_shentsize)];
	int shstrtab_offset = temp->sh_offset;
	int shstrtab_size = temp->sh_size;
	char buffer[shstrtab_size];

	while (i < elf_header->e_shnum)
	{
		temp = (void *)&elf_file[elf_header->e_shoff + (i * elf_header->e_shentsize)];
		int string_table_offset = shstrtab_offset + temp->sh_name;
		snprintf(buffer, shstrtab_size, "%s", &elf_file[string_table_offset]);
		if (strcmp(buffer, ".note.ABI-tag") == 0)
		{
			lseek(fd, string_table_offset, SEEK_SET);
			format_buffer(buffer, name);
			if (write(fd, buffer, strlen(".note.ABI-tag")) == -1)
			{
				fd = close(fd);
				munmap(elf_file, filesize);
				return -1;
			}
			res = 0;
			break;
		}
		i++;
	}

	fd = close(fd);
	munmap(elf_file, filesize);
	return res;
}

int modify_pt_note(Elf64_Ehdr *res,
				   Elf64_Shdr *section_header, char *file, int index)
{
	int fd = -1;
	Elf64_Phdr current_phdr;

	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	current_phdr.p_type = PT_LOAD;
	current_phdr.p_offset = section_header->sh_offset;
	current_phdr.p_vaddr = section_header->sh_addr;
	current_phdr.p_paddr = section_header->sh_addr;
	current_phdr.p_filesz = section_header->sh_size;
	current_phdr.p_memsz = section_header->sh_size;
	current_phdr.p_flags = (PF_X | PF_R);
	current_phdr.p_align = 0x1000;
	lseek(fd, res->e_phoff + (index * res->e_phentsize), SEEK_SET);
	if (write(fd, &current_phdr, res->e_phentsize) == -1)
	{
		fd = close(fd);
		return -1;
	}
	fd = close(fd);
	return 0;
}

int modify_entrypoint(Elf64_Ehdr *ehdr, uint64_t new_address, char *file)
{
	int fd = -1;
	Elf64_Ehdr *temp = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
	if (temp == NULL)
	{
		return -1;
	}

	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		free(temp);
		return -1;
	}
	fill_ehdr(temp, ehdr);
	temp->e_entry = new_address;
	if (write(fd, temp, ehdr->e_ehsize) == -1)
	{
		fd = close(fd);
		free(temp);
		return -1;
	}
	fill_ehdr(ehdr, temp);
	fd = close(fd);
	free(temp);
	return 0;
}

/* Map the file in the memory, localize the .got section and modify the
   corresponding entry of getenv by the custom base address*/
int got_hijack(Elf64_Ehdr *elf_header,
			   Elf64_Shdr *section_header, char *file, uint64_t base_address)
{
	int fd = -1;
	int shstrtab_offset = 0;
	int shstrtab_size = 0;
	int offset = 0;
	int i = 0;
	int filesize = elf_header->e_shoff +
				   (elf_header->e_shentsize * elf_header->e_shnum);
	Elf64_Shdr *temp;

	fd = open(file, O_RDWR);
	if (fd < 0)
	{
		fd = close(fd);
		return -1;
	}
	uint8_t *elf_file = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
	if (elf_file == MAP_FAILED)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}
	if (elf_file == MAP_FAILED)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}
	temp = (void *)&elf_file[elf_header->e_shoff + (elf_header->e_shstrndx *
													elf_header->e_shentsize)];
	shstrtab_offset = temp->sh_offset;
	shstrtab_size = temp->sh_size;
	char buffer[shstrtab_size];

	while (i < elf_header->e_shnum)
	{
		temp = (void *)&elf_file[elf_header->e_shoff +
								 (i * elf_header->e_shentsize)];
		int string_table_offset = shstrtab_offset + temp->sh_name;
		snprintf(buffer, shstrtab_size, "%s", &elf_file[string_table_offset]);

		if (strcmp(buffer, ".got.plt") == 0)
		{
			fill_shdr(section_header, temp);
			break;
		}
		i++;
	}
	offset = temp->sh_offset;

	lseek(fd, offset + GET_ENV_OFFSET, SEEK_SET);
	if (write(fd, &base_address, 8) == -1)
	{
		fd = close(fd);
		munmap(elf_file, filesize);
		return -1;
	}
	fd = close(fd);
	munmap(elf_file, filesize);
	return 0;
}