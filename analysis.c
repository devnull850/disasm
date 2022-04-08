#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/disasm.h"
#include "include/file.h"
#include "include/util.h"

int main(int argc, char *argv[]) {
	struct Bytes *raw;
	struct Elf64_bin *elf;
	char *filename;
	int option;

	switch (argc) {
		case 3:
			if (argv[1][0] != 0x2d) goto usage;
			if (argv[1][1] != 0x6c && argv[1][1] != 0x72) goto usage;
			option = argv[1][1] == 0x72 ? RECURSIVE : LINEAR;

			if (!(filename = malloc(strlen(argv[2]) + 1))) {
				handle_error("memory allocation for filename failed");
			}

			strncpy(filename, argv[2], strlen(argv[2]));
			break;

		case 2:
			if (!(filename = malloc(strlen(argv[1]) + 1))) {
				handle_error("memory allocation for filename failed");
			}

			strncpy(filename, argv[1], strlen(argv[1]));
			option = LINEAR;
			break;

		default:
			goto usage;
	}

	raw = get_raw_bytes(filename);
	free(filename);

	if (!is_elf(raw)) return EXIT_SUCCESS;
	elf = parse_elf(raw);
	free_raw_bytes(raw);

	disassemble(elf, option);
	free_elf(elf);

	return EXIT_SUCCESS;

usage:
	puts("Usage: ./analysis [-[l|r]] <filename>");
	return EXIT_SUCCESS;
}
