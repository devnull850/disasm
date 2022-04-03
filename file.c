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

struct Bytes *get_raw_bytes(const char *filename) {
    FILE *fd;
    struct Bytes *bytes;

    if (!(bytes = malloc(sizeof(struct Bytes)))) {
        handle_error("error allocating struct Bytes");
    }

    if (!(fd = fopen(filename, READ))) {
        handle_error("error opening file");
    }

	fseek(fd, 0, SEEK_END);
	bytes->size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	if (!(bytes->bytes = malloc(bytes->size))) {
        handle_error("error allocating bytes [struct Bytes]");
    }

	fread(bytes->bytes, 1, bytes->size, fd);

	if (fclose(fd) == EOF) {
        handle_error("error closing file");
    }

    return bytes;
}

int is_elf(struct Bytes *raw) {
    return *((uint32_t *)(raw->bytes)) == ELF;
}

int is_pe(struct Bytes *raw) {
    return *((uint16_t *)(raw->bytes)) == PE;
}

struct Elf64_bin *parse_elf(struct Bytes *raw) {
    struct Elf64_bin *elf;

    if (!(elf = malloc(sizeof(struct Elf64_bin)))) {
        handle_error("error allocating memory for ELF");
    }

    if (!(elf->ehdr = malloc(sizeof(Elf64_Ehdr)))) {
        handle_error("error allocating memory for ELF header");
    }

    memcpy(elf->ehdr, raw->bytes, sizeof(Elf64_Ehdr));

    if (!(elf->phdr = malloc(sizeof(Elf64_Phdr) * elf->ehdr->e_phnum))) {
        handle_error("error allocating memory for Program Headers");
    }

    if (!(elf->segments = malloc(sizeof(struct Segment) * elf->ehdr->e_phnum))) {
        handle_error("error allocating memory for Segments");
    }

    for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
        memcpy(elf->phdr + i, raw->bytes + elf->ehdr->e_phoff + i * elf->ehdr->e_phentsize,
                elf->ehdr->e_phentsize);

        elf->segments[i].phdr_index = i;
        if (!(elf->segments[i].bytes = malloc(elf->phdr[i].p_filesz))) {
            handle_error("error allocating memory for Segment bytes");
        }

        memcpy(elf->segments[i].bytes, raw->bytes + elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
    }

    return elf;
}

void free_raw_bytes(struct Bytes *b) {
    free(b->bytes);
    free(b);
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