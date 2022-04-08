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
	return g == CS_GRP_JUMP || g == CS_GRP_CALL || g == CS_GRP_RET || g == CS_GRP_IRET;
}

static int is_cs_cflow_ins(cs_insn *ins) {
	for (size_t i = 0; i < ins->detail->groups_count; ++i) {
		if (is_cs_cflow_group(ins->detail->groups[i])) {
			return 1;
		}
	}

	return 0;
}

static int is_cs_unconditional_cflow_ins(cs_insn *ins) {
	switch (ins->id) {
		case X86_INS_JMP:
		case X86_INS_LJMP:
		case X86_INS_RET:
		case X86_INS_RETF:
		case X86_INS_RETFQ:
			return 1;

		default:
			return 0;
	}
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
	uint8_t *p, b;
	struct AddressList *visited, *addr_queue;
	uint64_t target, addr;

	handle = open_capstone_handle();
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	for (size_t i = 0; i < elf->ehdr->e_phnum; ++i) {
		if (!(elf->phdr[i].p_flags & 1)) continue;

		if (elf->phdr[i].p_filesz != elf->segments[i].size) {
			p = elf->segments[i].bytes + elf->ehdr->e_entry;
			code_size = elf->segments[i].size - elf->ehdr->e_entry;
			target = elf->ehdr->e_entry;
		}
		else {
			p = elf->segments[i].bytes + (elf->ehdr->e_entry - elf->phdr[i].p_vaddr);
			code_size = elf->phdr[i].p_filesz;
			target = elf->ehdr->e_entry - elf->phdr[i].p_vaddr;
		}
		

		visited = new_address_list(elf->segments[i].size);
		addr_queue = new_address_list(elf->segments[i].size);

		flag = 1;

		while (flag) {
			if (!(count = cs_disasm(handle, p, code_size, 0, 0, &insn))) break;

			for (size_t j = 0; j < count; ++j) {
				printf("0x%0lx:\t%s\t\t%s\n",
					   target + insn[j].address, insn[j].mnemonic, insn[j].op_str);

				if (!contains(visited, target + insn[j].address)) {
					add_address(visited, target + insn[j].address);
				}

				if (is_cs_cflow_ins(insn + j)) {
					b = insn[j].bytes[1];

					if (!is_cs_unconditional_cflow_ins(insn + j)) {
						if (!contains(addr_queue, target + insn[j].address + insn[j].size)) {
							add_address(addr_queue, target + insn[j].address + insn[j].size);
						}
					}

					if (((b >> 7) & 1)) {
						b = 0 - b;
						target = (p - elf->segments[i].bytes) + insn[j].address + insn[j].size;
						target -= b;
					}
					else {
						target = (p - elf->segments[i].bytes) + b + insn[j].address + insn[j].size;
					}

					if (contains(visited, target)) {
						if (is_empty(addr_queue)) {
							flag = 0;
						}
						else {
							target = remove_address(addr_queue);
							add_address(visited, target);
							p = elf->segments[i].bytes + target;
							code_size = elf->segments[i].size - (p - elf->segments[i].bytes);
						}

						break;
					}

					p = elf->segments[i].bytes + target;
					code_size = elf->segments[i].size - (p - elf->segments[i].bytes);

					break;
				}

				if (insn[j].address + insn[j].size == code_size) flag = 0;
			}

			cs_free(insn, count);
		}

		free_address_list(visited);
		free_address_list(addr_queue);
	}

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