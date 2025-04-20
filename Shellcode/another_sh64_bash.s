
section .text
global _start
_start:
    ; Clear registers
    xor rdx, rdx    ; Clear rdx for null terminator
    xor rax, rax    ; Clear rax

    ; Push the command string "echo hello; ls -la" (in reverse)
    push rdx        ; Push null terminator
    mov rax, 'a'    ; Build command string piece by piece
    push rax
    mov rax, 'ls -l'
    push rax
    mov rax, 'llo; '
    push rax
    mov rax, 'ho he'
    push rax
    mov rax, 'ec'
    push rax
    mov r8, rsp     ; Save pointer to command string

    ; Push "-c" (in reverse)
    push rdx        ; Push null terminator
    mov rax, 'c-'
    push rax
    mov r9, rsp     ; Save pointer to "-c"

    ; Push "/bin/bash" (in reverse)
    push rdx        ; Push null terminator
    mov rax, 'bash'
    push rax
    mov rax, '/bin/'
    push rax
    mov r10, rsp    ; Save pointer to "/bin/bash"

    ; Set up array of pointers for execve
    push rdx        ; NULL terminator
    push r8         ; Push pointer to command string
    push r9         ; Push pointer to "-c"
    push r10        ; Push pointer to "/bin/bash"
    mov rdi, r10    ; First argument: "/bin/bash"
    mov rsi, rsp    ; Second argument: pointer to array

    ; Execute execve syscall
    push 59
    pop rax         ; syscall number for execve
    syscall
