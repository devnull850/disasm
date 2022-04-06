#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdlib.h>

struct AddressList {
    uint64_t *address;
    size_t size;
    size_t allocated;
};

struct AddressList *new_address_list(size_t);
void free_address_list(struct AddressList *);

void add_address(struct AddressList *, uint64_t);

uint64_t remove_address(struct AddressList *);

size_t get_size(struct AddressList *);

int is_empty(struct AddressList *);

int contains(struct AddressList *, uint64_t);

void handle_error(const char *);

#endif /* UTIL_H */