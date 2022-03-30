all: analysis

analysis: analysis.o file.o
	gcc -Wall -Werror -g -o analysis analysis.o file.o -lcapstone

analysis.o: analysis.c
	gcc -c analysis.c

file.o: file.c
	gcc -c file.c

.PHONY:
clean:
	rm analysis analysis.o file.o