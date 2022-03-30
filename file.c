#include <stdio.h>
#include <string.h>

#include "file.h"

const char READ[] = "rb";

const uint32_t ELF = 0x464c457f;
const uint16_t PE = 0x5a4d;

static void handle_error(const char *errmsg) {
    fprintf(stderr, "%s\n", errmsg);
    exit(EXIT_FAILURE);
}

uint8_t *get_raw_bytes(const char *filename) {
    FILE *fd;
    long bytes;
    uint8_t *raw;

    if (!(fd = fopen(filename, READ))) {
        handle_error("error opening file");
    }

	fseek(fd, 0, SEEK_END);
	bytes = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	if (!(raw = malloc(bytes))) {
        handle_error("error allocating memory");
    }

	fread(raw, 1, bytes, fd);

	if (fclose(fd) == EOF) {
        handle_error("error closing file");
    }

    return raw;
}

int is_elf(uint8_t *raw) {
    return *((uint32_t *)raw) == ELF;
}

int is_pe(uint8_t *raw) {
    return *((uint16_t *)raw) == PE;
}

struct Elf64_bin *parse_elf(uint8_t *raw) {
    struct Elf64_bin *elf;

    if (!(elf = malloc(sizeof(struct Elf64_bin)))) {
        handle_error("error allocating memory for ELF");
    }

    if (!(elf->ehdr = malloc(sizeof(Elf64_Ehdr)))) {
        handle_error("error allocating memory for ELF header");
    }

    memcpy(elf->ehdr, raw, sizeof(Elf64_Ehdr));

    if (!(elf->phdr = malloc(sizeof(Elf64_Phdr) * elf->ehdr->e_phnum))) {
        handle_error("error allocating memory for Program Headers");
    }

    if (!(elf->segments = malloc(sizeof(struct Segment) * elf->ehdr->e_phnum))) {
        handle_error("error allocating memory for Segments");
    }

    for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
        memcpy(elf->phdr + i, raw + elf->ehdr->e_phoff + i * elf->ehdr->e_phentsize,
                elf->ehdr->e_phentsize);

        elf->segments[i].phdr_index = i;
        if (!(elf->segments[i].bytes = malloc(elf->phdr[i].p_filesz))) {
            handle_error("error allocating memory for Segment bytes");
        }

        memcpy(elf->segments[i].bytes, raw + elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
    }

    return elf;
}

void free_elf(struct Elf64_bin *elf) {
    for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
        free(elf->segments[i].bytes);
    }

    free(elf->segments);
    free(elf->phdr);
    free(elf->ehdr);
    free(elf);
}