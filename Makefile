all:
	gcc -Wall -Werror -o analysis analysis.c

.PHONY:
clean:
	rm analysis