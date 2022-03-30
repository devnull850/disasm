#ifndef FILE_H
#define FILE_H

#include <elf.h>
#include <stdint.h>
#include <stdlib.h>

struct Segment {
    size_t phdr_index;
    uint8_t *bytes;
};

struct Elf64_bin {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    struct Segment *segments;
};

uint8_t *get_raw_bytes(const char *);

int is_elf(uint8_t *);
int is_pe(uint8_t *);

struct Elf64_bin *parse_elf(uint8_t *);
void free_elf(struct Elf64_bin *);

#endif /* FILE_H */