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

struct Bytes {
    uint8_t *bytes;
    size_t size;
};

struct Bytes *get_raw_bytes(const char *);
void free_raw_bytes(struct Bytes *);

int is_elf(struct Bytes *);
int is_pe(struct Bytes *);

struct Elf64_bin *parse_elf(struct Bytes *);
void free_elf(struct Elf64_bin *);

#endif /* FILE_H */