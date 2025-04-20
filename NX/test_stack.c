#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];
    void (*function_pointer)();
    printf("Enter shellcode: ");
    gets(buffer);  // Vulnerable function
    function_pointer = (void (*)())buffer;
    function_pointer();  // Attempt to execute code on the stack
}

int main() {
    vulnerable_function();
    return 0;
}
