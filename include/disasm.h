#ifndef DISASM_H
#define DISASM_H

#include "file.h"

enum Disassembly {
    LINEAR = 0,
    RECURSIVE
};

void disassemble(struct Elf64_bin *, enum Disassembly);

#endif /* DISASM_H */