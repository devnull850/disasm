all:
	gcc -Wall -Werror -o analysis analysis.c -lcapstone

.PHONY:
clean:
	rm analysis