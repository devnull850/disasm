#include <stdio.h>

#include "../include/util.h"

struct AddressList *new_address_list(void) {
    struct AddressList *list;

    if (!(list = malloc(sizeof(struct AddressList)))) {
        handle_error("allocating memory for struct AddressList");
    }

    list->allocated = 0x10;
    list->size = 0;

    if (!(list->address = malloc(list->allocated * sizeof(uint64_t)))) {
        handle_error("allocating memory for address list");
    }

    return list;
}

void free_address_list(struct AddressList *list) {
    free(list->address);
    free(list);
}

void add_address(struct AddressList *list, uint64_t addr) {
    if (list->size == list->allocated) {
        if (!(list->address = realloc(list->address, (list->allocated += 0x10)))) {
            handle_error("reallocating memory for address list");
        }
    }

    list->address[list->size] = addr;
    ++list->size;
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