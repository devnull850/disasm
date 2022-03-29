#include <capstone/capstone.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
	FILE *fd;
	uint8_t *raw;
	uint64_t size;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	csh handle;
	cs_insn *insn;
	size_t count;

	fd = fopen("a.out", "rb");

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	raw = malloc(size);
	fread(raw, 1, size, fd);

	fclose(fd);

	if (*((uint32_t *)raw) != 0x464c457f) goto cleanup;

	ehdr = (Elf64_Ehdr *) raw;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		goto cleanup;

	phdr = (Elf64_Phdr *) (raw + ehdr->e_phoff);

	for (size_t i = 0; i < ehdr->e_phnum; ++i) {
		if (!(phdr->p_flags & 1)) continue;

		count = cs_disasm(handle, raw + phdr->p_offset, phdr->p_filesz, phdr->p_vaddr, 0, &insn);

		for (size_t j = 0; j < count; ++j) {
			printf("0x%0lx:\t%s\t\t%s\n",
				insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
		phdr += 1;
	}

	cs_close(&handle);

cleanup:
	free(raw);

	return EXIT_SUCCESS;
}
