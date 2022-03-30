#include <capstone/capstone.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"

int main(int argc, char *argv[]) {
	uint8_t *raw;
	struct Elf64_bin *elf;
	csh handle;
	cs_insn *insn;
	size_t count;
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

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		exit(EXIT_FAILURE);

	for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
		if (!(elf->phdr[i].p_flags & 1)) continue;

		count = cs_disasm(handle, elf->segments[i].bytes, elf->phdr[i].p_filesz,
				elf->phdr[i].p_vaddr, 0, &insn);

		for (size_t j = 0; j < count; ++j) {
			printf("0x%0lx:\t%s\t\t%s\n",
				insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	}

	cs_close(&handle);
	free_elf(elf);

	return EXIT_SUCCESS;
}
