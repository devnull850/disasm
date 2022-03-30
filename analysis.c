#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disasm.h"
#include "file.h"

int main(int argc, char *argv[]) {
	uint8_t *raw;
	struct Elf64_bin *elf;
	char *filename;

	if (argc < 2) {
		puts("Usage: ./analysis <filename>");
		return EXIT_SUCCESS;
	}

	if (!(filename = malloc(strlen(argv[1]) + 1))) {
		fprintf(stderr, "memory allocation for filename failed");
		exit(EXIT_FAILURE);
	}

	strncpy(filename, argv[1], strlen(argv[1]));

	raw = get_raw_bytes(filename);
	free(filename);

	if (!is_elf(raw)) return EXIT_SUCCESS;
	elf = parse_elf(raw);
	free(raw);

	disassemble(elf);
	free_elf(elf);

	return EXIT_SUCCESS;
}
