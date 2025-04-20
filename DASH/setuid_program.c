
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <uid>\n", argv[0]);
        return 1;
    }

    uid_t uid = atoi(argv[1]);
    printf("Setting UID to: %d\n", uid);

    if (setuid(uid) == -1) {
        perror("setuid failed");
        return 1;
    }

    system("/bin/sh"); // Launch a shell with the new UID
    return 0;
}
