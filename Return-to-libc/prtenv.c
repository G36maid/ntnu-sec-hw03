
#include <stdio.h>
#include <stdlib.h>

void main() {
    // Get the address of the MYSHELL environment variable
    char* shell = getenv("MYSHELL");
    if (shell) {
        // Print the address of the environment variable
        printf("%x\n", (unsigned int)shell);
    }
}
