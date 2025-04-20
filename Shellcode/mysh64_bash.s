section .text
  global _start
    _start:
        BITS 64
        jmp short two
    one:
        pop rbx           ; rbx points to the string area

        ; Set up /bin/bash string termination
        xor al, al
        mov [rbx+9], al  ; Terminate /bin/bash

        ; Set up -c string termination
        mov [rbx+12], al ; Terminate -c

        ; Set up command string termination
        mov [rbx+31], al ; Terminate the command string

        ; Set up argv array
        lea rax, [rbx]        ; /bin/bash string
        mov [rbx+32], rax     ; argv[0]

        lea rax, [rbx+10]     ; -c string
        mov [rbx+40], rax     ; argv[1]

        lea rax, [rbx+13]     ; command string
        mov [rbx+48], rax     ; argv[2]

        xor rax, rax
        mov [rbx+56], rax     ; argv[3] = NULL

        ; Execute execve
        mov rdi, rbx          ; First arg: pathname
        lea rsi, [rbx+32]     ; Second arg: argv array
        xor rdx, rdx          ; Third arg: envp = NULL
        mov al, 59            ; syscall number for execve
        syscall

    two:
        call one
        ; String table
        db '/bin/bash'    ; 9 bytes
        db 0xFF
        db '-c'           ; 2 bytes
        db 0xFF
        db 'echo hello; ls -la'  ; 18 bytes
        db 0xFF
        ; Space for argv array (4 pointers = 32 bytes)
        db 'AAAAAAAA'     ; argv[0]
        db 'BBBBBBBB'     ; argv[1]
        db 'CCCCCCCC'     ; argv[2]
        db 'DDDDDDDD'     ; argv[3]
