
section .text
  global _start
    _start:
        BITS 64
        jmp short two
    one:
        pop rbx                ; Get address of "/usr/bin/env"

        ; Terminate the command string
        xor al, al
        mov [rbx+11], al      ; Null terminate "/usr/bin/env"

        ; Set up env strings
        mov [rbx+12], rbx     ; Store address of command as argv[0]
        mov [rbx+28], rax     ; Null terminate argv array

        ; Store addresses of environment strings
        lea rcx, [rbx+20]     ; Address of "aaa=hello"
        mov [rbx+40], rcx     ; env[0]
        lea rcx, [rbx+30]     ; Address of "bbb=world"
        mov [rbx+48], rcx     ; env[1]
        lea rcx, [rbx+40]     ; Address of "ccc=hello world"
        mov [rbx+56], rcx     ; env[2]
        mov qword [rbx+64], 0 ; env[3] = NULL

        ; Execute execve
        mov rdi, rbx          ; First arg: command path
        lea rsi, [rbx+12]     ; Second arg: argv array
        lea rdx, [rbx+40]     ; Third arg: envp array
        mov rax, 59           ; syscall number for execve
        syscall

    two:
        call one
        ; Command and strings
        db '/usr/bin/env', 0      ; The command string
        db 'AAAAAAAA'             ; Placeholder for argv[0]
        db 'BBBBBBBB'             ; Null terminator for argv
        db 'aaa=hello', 0         ; env[0]
        db 'bbb=world', 0         ; env[1]
        db 'ccc=hello world', 0   ; env[2]
        db 'AAAAAAAA'             ; Placeholder for env array
        db 'BBBBBBBB'
        db 'CCCCCCCC'
        db 'DDDDDDDD'
