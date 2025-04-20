#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *heap_memory = (char *)malloc(64);
    void (*function_pointer)();
    printf("Enter shellcode: ");
    gets(heap_memory);  // Vulnerable function
    function_pointer = (void (*)())heap_memory;
    function_pointer();  // Attempt to execute code on the heap
    free(heap_memory);
    return 0;
}
