#include <stdio.h>

#include "../include/util.h"

struct AddressList *new_address_list(size_t max_size) {
    struct AddressList *list;

    if (!(list = malloc(sizeof(struct AddressList)))) {
        handle_error("allocating memory for struct AddressList");
    }

    if (!(list->address = malloc(max_size * sizeof(uint64_t)))) {
        handle_error("allocating memory for address list");
    }

    list->allocated = max_size;
    list->size = 0;

    return list;
}

void free_address_list(struct AddressList *list) {
    free(list->address);
    free(list);
}

void add_address(struct AddressList *list, uint64_t addr) {
    if (list->size == list->allocated) {
        handle_error("max size is attempting to be exceeded");
    }

    list->address[list->size] = addr;
    ++list->size;
}

uint64_t remove_address(struct AddressList *list) {
    uint64_t addr;

    if (is_empty(list)) {
        handle_error("illegal operation on an empty list");
    }

    addr = list->address[list->size-1];
    --list->size;

    return addr;
}

size_t get_size(struct AddressList *list) {
    return list->size;
}

int is_empty(struct AddressList *list) {
    return !list->size;
}

int contains(struct AddressList *list, uint64_t addr) {
    for (size_t i = 0; i < list->size; ++i) {
        if (list->address[i] == addr) {
            return 1;
        }
    }

    return 0;
}

void handle_error(const char *errmsg) {
    fprintf(stderr, "%s\n", errmsg);
    exit(EXIT_FAILURE);
}