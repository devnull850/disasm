FLAGS=-Wall -Werror -g
OBJ=analysis.o file.o disasm.o

all: analysis

analysis: $(OBJ)
	gcc $(FLAGS) -o analysis $(OBJ) -lcapstone

analysis.o: analysis.c
	gcc -c analysis.c

file.o: file.c
	gcc -c file.c

disasm.o: disasm.c
	gcc -c disasm.c

.PHONY:
clean:
	rm analysis $(OBJ)