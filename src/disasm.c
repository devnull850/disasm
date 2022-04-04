#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>

#include "../include/disasm.h"
#include "../include/util.h"

static csh open_capstone_handle(void) {
	csh handle;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		handle_error("opening capstone handle");

	return handle;
}

static int is_cs_cflow_group(uint8_t g) {
	return g == CS_GRP_JUMP || g == CS_GRP_CALL ||
		g == CS_GRP_RET || g == CS_GRP_IRET;
}

static int is_cs_cflow_ins(cs_insn *ins) {
	for (size_t i = 0; i < ins->detail->groups_count; ++i) {
		if (is_cs_cflow_group(ins->detail->groups[i])) {
			return 1;
		}
	}

	return 0;
}

static void linear_disassemble(struct Elf64_bin *elf) {
    csh handle;
	cs_insn *insn;
	size_t count;

    handle = open_capstone_handle();

	for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
		if (!(elf->phdr[i].p_flags & 1)) continue;

		count = cs_disasm(handle, elf->segments[i].bytes, elf->phdr[i].p_filesz,
				elf->phdr[i].p_vaddr, 0, &insn);

		for (size_t j = 0; j < count; ++j) {
			printf("0x%0lx:\t%s\t\t%s\n",
				insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}

		cs_free(insn, count);
	}

	cs_close(&handle);
}

static void recursive_disassemble(struct Elf64_bin *elf) {
	csh handle;
	cs_insn *insn;
	size_t count, code_size;
	int flag;
	uint8_t *p, *p1, b;
	struct AddressList *list;
	uint64_t target;

    handle = open_capstone_handle();
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	list = new_address_list();

	for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
		if (!(elf->phdr[i].p_flags & 1)) continue;

		p = elf->segments[i].bytes + elf->ehdr->e_entry;
		p1 = elf->segments[i].bytes;
		code_size = elf->segments[i].size - elf->ehdr->e_entry;

		flag = 1;

		while (flag) {
			count = cs_disasm(handle, p, code_size, 0, 0, &insn);
			if (!count) break;

			for (size_t j = 0; j < count; ++j) {
				printf("0x%0lx:\t%s\t\t%s\n",
					insn[j].address, insn[j].mnemonic, insn[j].op_str);

				if (is_cs_cflow_ins(insn+j)) {
					b = insn[j].bytes[1];

					if (((b>>7) & 1)) {
						b = 0 - b;
						target = (p - p1) + insn[j].address + insn[j].size;
						target -= b;
					}
					else {
						target = (p - p1) + b + insn[j].address + insn[j].size;
					}

					if (contains(list, target)) {
						flag = 0;
						break;
					}

					add_address(list, target);
					p = p1 + target;
					code_size = (p1 + target) - elf->segments[i].bytes;

					break;
				}
			}

			cs_free(insn, count);
		}
	}

	free_address_list(list);
	cs_close(&handle);
}

void disassemble(struct Elf64_bin *elf, enum Disassembly type) {
	switch (type) {
		case LINEAR:
			linear_disassemble(elf);
			break;
		case RECURSIVE:
			recursive_disassemble(elf);
			break;
		default:
			handle_error("invalid disassembly type");
	}
}