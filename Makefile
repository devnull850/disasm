FLAGS=-Wall -Werror -g
OBJ=analysis.o file.o disasm.o util.o

all: analysis

analysis: $(OBJ)
	gcc $(FLAGS) -o analysis $(OBJ) -lcapstone

analysis.o: analysis.c
	gcc -c analysis.c

file.o: src/file.c
	gcc -c src/file.c

disasm.o: src/disasm.c
	gcc -c src/disasm.c

util.o: src/util.c
	gcc -c src/util.c

.PHONY:
clean:
	rm analysis $(OBJ)
