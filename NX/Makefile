{{INSERTED_CODE}}
CC = gcc
CFLAGS = -g -Wall

all: test_heap test_stack

test_heap: test_heap.c
    $(CC) $(CFLAGS) -o test_heap test_heap.c

test_stack: test_stack.c
    $(CC) $(CFLAGS) -z execstack -o test_stack test_stack.c

clean:
    rm -f test_heap test_stack
