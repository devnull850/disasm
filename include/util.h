#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdlib.h>

struct AddressList {
    uint64_t *address;
    size_t allocated;
    size_t size;
};

struct AddressList *new_address_list(void);
void free_address_list(struct AddressList *);

void add_address(struct AddressList *, uint64_t);

size_t get_size(struct AddressList *);

int is_empty(struct AddressList *);

int contains(struct AddressList *, uint64_t);

void handle_error(const char *);

#endif /* UTIL_H */