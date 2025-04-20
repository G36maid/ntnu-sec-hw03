# Information Security HW03


## 3.1 SEED Lab (20 pts)
Shellcode Development Lab
https://seedsecuritylabs.org/Labs_20.04/Software/Shellcode/

### Task1 


## 3.2 SEED Lab (30 pts)
Return-to-libc Attack Lab
https://seedsecuritylabs.org/Labs_20.04/Software/Return_to_
Libc/






## 3.3 NX (10 pts)
In this course, I have introduced a defensive mechanism called non-executable
stack. I also told you that the only difference between NX enabled and
NX disabled programs is one bit. Actually, this defensive mechanism is im-
plemented on CPU. Please check that if this defensive approach still works
when NX is disabled in BIOS. Also you need to check if the malicious code
is in heap, will the attack work?

## 3.4 Password Guess (20 pts)
Please read the following code.
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main()
{
    FILE *pFile = fopen("/dev/random", "rb");

    uint32_t guess = 0, secret = 0;

    if (pFile == NULL)
    {
        perror("Error");
        return 0;
    }

    fread(&secret, 4, 1, pFile);

    while (1)
    {
        printf("Please enter your guess: ");
        scanf("%u", &guess);

        if (guess == secret)
        {
            break;
        }

        printf("Wrong guess! Please guess again.\n");
    }

    printf("Congratulation! The secret is uiwebqwhec12!\n");

    return 0;
}
```
I think you should know the function of this code. Please write a lab
to show how to get the secret from binary only. Note that in your lab, you
need to show at least four ways to get the secret. I give you this code so
that you can build the code yourself. Undoubtedly, read the code directly
is not included.



## 3.5 Defeat DASH Countermeasure (20 pts)
In this class, I have introduced how DASH protect your system from Set-
UID programs. Now we want to beat this countermeasure. The concept is
very simple. We can use setuid to set all process-related user ID’s to the
input uid. The problem is, the root uid is 0 and you all know that strcpy()
stops when encountering zero. How to solve this problem? Please write
down your idea and launch your attack to show it works.
Of course, you can use any approaches. For your convenience, I will
give you one hint.
1 // The functions sprintf () writes a formatted string (
including the terminating null byte ('\0')) to str.
2 int sprintf (char *str , const char *format , ...);
