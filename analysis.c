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

	if (argc < 2) {
		puts("Usage: ./analysis <filename>");
		return EXIT_SUCCESS;
	}

	if (!(filename = malloc(strlen(argv[1]) + 1))) {
		handle_error("memory allocation for filename failed");
	}

	strncpy(filename, argv[1], strlen(argv[1]));

	raw = get_raw_bytes(filename);
	free(filename);

	if (!is_elf(raw)) return EXIT_SUCCESS;
	elf = parse_elf(raw);
	free_raw_bytes(raw);

	disassemble(elf, RECURSIVE);
	free_elf(elf);

	return EXIT_SUCCESS;
}
