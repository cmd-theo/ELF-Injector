
#include <stdlib.h>

#include <argp.h>
#include <bfd.h>

#include <err.h>
#include <string.h>

#include "../include/parser.h"

const char *argp_program_version = "isos_inject 1.0";
const char *argp_program_bug_address = "<theo.boulaire@etudiant.univ-rennes1.fr>";

static char doc[] = "isos_inject is used to inject a completely new code section"
                    " into an ELF binary ";
static char args_doc[] = "ELF_PATH_FILE INJECTED_CODE SECTION_NAME BASE_ADDRESS "
                         "M_ENTRY : [true / false] ";
static struct argp_option options[] = {{0}};

struct arguments
{
	char *args[5];
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key)
	{
	case ARGP_KEY_ARG:
		if (state->arg_num >= 5)
			/* Too many arguments. */
			argp_usage(state);

		arguments->args[state->arg_num] = arg;

		break;

	case ARGP_KEY_END:
		if (state->arg_num < 5)
			argp_usage(state);
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int main(int argc, char **argv)
{
	int status;
	int index_pt;
	int status_pt;
	int size_arg2;

	struct arguments arguments;

	Elf64_Ehdr elf_header;
	Elf64_Shdr current_shdr;

	uint64_t base_address = 0;
	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	bfd_init();
	bfd *current_file = bfd_openr(arguments.args[0], NULL);

	if (current_file == NULL)
	{
		errx(EXIT_FAILURE, "\n[!] error : the target file doesn't exist!");
	}

	if (bfd_check_format(current_file, bfd_object))
	{
		printf("[*] File Format : %s\n", find_bin_format(current_file));
		printf("[*] Architecture size : %d bits\n", find_arch(current_file));
		if (is_executable(current_file->flags))
		{
			printf("[*] This file is an executable\n");
		}
		else
		{
			return -1;
		}
	}
	else
	{
		printf("[!] This file is not executable.\n");
		return -1;
	}
	bfd_close(current_file);

	status = elf_header_parser(&elf_header, arguments.args[0]);
	if (status == -1)
	{
		printf("[!] Problem while parsing the elf header...exiting\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("[*] Successfully parsed the header.\n");
	}

	status_pt = find_pt_note(&elf_header, arguments.args[0], &index_pt);
	if (status_pt == -1)
	{
		printf("[!] Cannot find PT_NOTE in progam headers\n");
		return EXIT_FAILURE;
	}
	else
	{
		printf("[*] PT_NOTE successfully find : Program header[%d].\n", index_pt);
	}

	long f_offset = inject_code(arguments.args[0], arguments.args[1], 
	                                               arguments.args[4]);

	if (f_offset == -1)
	{
		printf("[!] Error while injecting the binary, leaving...\n");
		return -1;
	}
	else
	{
		printf("[*] Binary injected at offset: #%ld\n", f_offset);
		char *eptr;
		base_address = strtol(arguments.args[3], &eptr, 10);
		int shift = (f_offset - base_address) % 4096;
		base_address += shift;
		printf("[*] address of injection with the good alignment : %ld\n",
			   base_address);
	}

	int indexsh = find_index_section(&elf_header,
									 &current_shdr, arguments.args[0]);
	if (indexsh <= 0)
	{
		printf("[*] Error cannot find .note.abi section leaving... \n");
		return EXIT_FAILURE;
	}
	printf("[*] Index of section .note.abi : %d\n", indexsh);
	if (modify_section(&elf_header, &current_shdr, indexsh,
					   bin_size(arguments.args[1]), arguments.args[0],
					   base_address, f_offset) == -1)
	{
		printf("[*] Error cannot modify .note.abi section header... \n");
		return EXIT_FAILURE;
	}
	printf("[*] .note.abi section header modified\n");
	if (reorder_section_hdr(&elf_header, arguments.args[0], indexsh) == -1)
	{
		printf("[*] problem during the reordering of the" 
		       "sections headers leaving...\n");
		return EXIT_FAILURE;
	}
	printf("[*] Successfully calibrate the sections headers\n");
	size_arg2 = strlen(arguments.args[2]);
	if (modify_name_section(&elf_header, arguments.args[0],
							arguments.args[2], size_arg2) != -1)
	{
		printf("[*] Successfully changed the new section name\n");
	}
	if (modify_pt_note(&elf_header, &current_shdr,
					   arguments.args[0], index_pt - 1) == -1)
	{
		printf("[*] problem during the modification on the program header\n");
		return EXIT_FAILURE;
	}
	printf("[*] Successfully changed the PT.NOTE program header\n");

	if (strcmp(arguments.args[4], "true") == 0)
	{
		printf("[*] Modifying the entry point..\n");
		printf("[*] original entry = %lu..\n", elf_header.e_entry);
		if (modify_entrypoint(&elf_header,
							  base_address, arguments.args[0]) == -1)
		{
			printf("[*] Problem during elf header modification...\n");
			return EXIT_FAILURE;
		}
		printf("[*] Successfully modified the elf header (e_entry = %lu)\n",
			   elf_header.e_entry);
	}
	else
	{
		if (got_hijack(&elf_header, &current_shdr,
					   arguments.args[0], base_address) != -1)
		{
			printf("[*] Successfully Hijacked the got \n");
		}
	}

	exit(0);
}
