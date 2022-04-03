FLAGS=-Wall -Werror -g
OBJ=analysis.o file.o disasm.o

all: analysis

analysis: $(OBJ)
	gcc $(FLAGS) -o analysis $(OBJ) -lcapstone

analysis.o: analysis.c
	gcc -c analysis.c

file.o: src/file.c
	gcc -c src/file.c

disasm.o: src/disasm.c
	gcc -c src/disasm.c

.PHONY:
clean:
	rm analysis $(OBJ)
