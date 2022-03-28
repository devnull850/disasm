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

	fd = fopen("a.out", "rb");

	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	raw = malloc(size);
	fread(raw, 1, size, fd);

	fclose(fd);

	if (*((uint32_t *)raw) != 0x464c457f) goto cleanup;

	ehdr = (Elf64_Ehdr *) raw;

	for (size_t i = 0; i < ehdr->e_phnum; ++i) {
		phdr = (Elf64_Phdr *) (raw + ehdr->e_phoff + i * ehdr->e_phoff);
		if (!(phdr->p_flags & 1)) continue;

		for (size_t j = phdr->p_offset; j < phdr->p_offset + phdr->p_filesz; j+=2) {
			printf("%02x", raw[j]);
			if (raw[j]) printf("%02x", raw[j+1]);
			else break;
			putchar((j+1-phdr->p_offset) % 0x10 != 0xf ? 0x20 : 0x0a);
		}

		putchar(0x0a);
	}

cleanup:
	free(raw);

	return EXIT_SUCCESS;
}
