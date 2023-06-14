BITS 64
SECTION .text
global main

main:
    ; save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    ; Je suis trop un hacker ! 
    mov r8, 0x2121212121210a21  
    mov r9, 0x2072656b63616820
    mov r10,0x6e7520706f727420
    mov r11,0x7369757320654a20
    
   ; load the string onto the stack
    push r8
    push r9
    push r10
    push r11
    
    ; print the string
    mov rax, 1
    mov rdi, 1
    mov rsi, rsp
    mov rdx, 26
    syscall


    ; load context
    pop r8
    pop r9
    pop r10
    pop r11 


    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret