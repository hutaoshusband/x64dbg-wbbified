option casemap:none
EXTERN gRegisterAvxAvailable:DWORD
EXTERN gRegisterPhase:DWORD
EXTERN gRegisterStack:QWORD
EXTERN gRegisterGeneral:QWORD
EXTERN gRegisterFlags:QWORD
EXTERN gRegisterMxCsr:DWORD
EXTERN gRegisterMxCsrInput:DWORD
EXTERN gRegisterSeed:BYTE
EXTERN gRegisterXmm:BYTE
EXTERN gRegisterYmm:BYTE
PUBLIC RegisterProbe
PUBLIC RegisterStop
.code
RegisterProbe PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 520
    .allocstack 520
    fxsave [rsp]
    .savexmm128 xmm6, 256
    .savexmm128 xmm7, 272
    .savexmm128 xmm8, 288
    .savexmm128 xmm9, 304
    .savexmm128 xmm10, 320
    .savexmm128 xmm11, 336
    .savexmm128 xmm12, 352
    .savexmm128 xmm13, 368
    .savexmm128 xmm14, 384
    .savexmm128 xmm15, 400
    .endprolog
    mov QWORD PTR [gRegisterStack], rsp
    ldmxcsr DWORD PTR [gRegisterMxCsrInput]
    cmp DWORD PTR [gRegisterAvxAvailable], 0
    je load_sse
    vmovdqu ymm0, YMMWORD PTR [gRegisterSeed+0]
    vmovdqu ymm1, YMMWORD PTR [gRegisterSeed+32]
    vmovdqu ymm2, YMMWORD PTR [gRegisterSeed+64]
    vmovdqu ymm3, YMMWORD PTR [gRegisterSeed+96]
    vmovdqu ymm4, YMMWORD PTR [gRegisterSeed+128]
    vmovdqu ymm5, YMMWORD PTR [gRegisterSeed+160]
    vmovdqu ymm6, YMMWORD PTR [gRegisterSeed+192]
    vmovdqu ymm7, YMMWORD PTR [gRegisterSeed+224]
    vmovdqu ymm8, YMMWORD PTR [gRegisterSeed+256]
    vmovdqu ymm9, YMMWORD PTR [gRegisterSeed+288]
    vmovdqu ymm10, YMMWORD PTR [gRegisterSeed+320]
    vmovdqu ymm11, YMMWORD PTR [gRegisterSeed+352]
    vmovdqu ymm12, YMMWORD PTR [gRegisterSeed+384]
    vmovdqu ymm13, YMMWORD PTR [gRegisterSeed+416]
    vmovdqu ymm14, YMMWORD PTR [gRegisterSeed+448]
    vmovdqu ymm15, YMMWORD PTR [gRegisterSeed+480]
    jmp registers_ready
load_sse:
    movdqu xmm0, XMMWORD PTR [gRegisterSeed+0]
    movdqu xmm1, XMMWORD PTR [gRegisterSeed+32]
    movdqu xmm2, XMMWORD PTR [gRegisterSeed+64]
    movdqu xmm3, XMMWORD PTR [gRegisterSeed+96]
    movdqu xmm4, XMMWORD PTR [gRegisterSeed+128]
    movdqu xmm5, XMMWORD PTR [gRegisterSeed+160]
    movdqu xmm6, XMMWORD PTR [gRegisterSeed+192]
    movdqu xmm7, XMMWORD PTR [gRegisterSeed+224]
    movdqu xmm8, XMMWORD PTR [gRegisterSeed+256]
    movdqu xmm9, XMMWORD PTR [gRegisterSeed+288]
    movdqu xmm10, XMMWORD PTR [gRegisterSeed+320]
    movdqu xmm11, XMMWORD PTR [gRegisterSeed+352]
    movdqu xmm12, XMMWORD PTR [gRegisterSeed+384]
    movdqu xmm13, XMMWORD PTR [gRegisterSeed+416]
    movdqu xmm14, XMMWORD PTR [gRegisterSeed+448]
    movdqu xmm15, XMMWORD PTR [gRegisterSeed+480]
registers_ready:
    xor eax, eax
    stc
    mov rax, 01020304011223300h
    mov rbx, 01020304011223301h
    mov rcx, 01020304011223302h
    mov rdx, 01020304011223303h
    mov rsi, 01020304011223304h
    mov rdi, 01020304011223305h
    mov rbp, 01020304011223306h
    mov r8, 01020304011223308h
    mov r9, 01020304011223309h
    mov r10, 0102030401122330Ah
    mov r11, 0102030401122330Bh
    mov r12, 0102030401122330Ch
    mov r13, 0102030401122330Dh
    mov r14, 0102030401122330Eh
    mov r15, 0102030401122330Fh
RegisterStop LABEL NEAR
    nop
    mov QWORD PTR [gRegisterGeneral+0], rax
    mov QWORD PTR [gRegisterGeneral+8], rbx
    mov QWORD PTR [gRegisterGeneral+16], rcx
    mov QWORD PTR [gRegisterGeneral+24], rdx
    mov QWORD PTR [gRegisterGeneral+32], rsi
    mov QWORD PTR [gRegisterGeneral+40], rdi
    mov QWORD PTR [gRegisterGeneral+48], rbp
    mov QWORD PTR [gRegisterGeneral+56], rsp
    mov QWORD PTR [gRegisterGeneral+64], r8
    mov QWORD PTR [gRegisterGeneral+72], r9
    mov QWORD PTR [gRegisterGeneral+80], r10
    mov QWORD PTR [gRegisterGeneral+88], r11
    mov QWORD PTR [gRegisterGeneral+96], r12
    mov QWORD PTR [gRegisterGeneral+104], r13
    mov QWORD PTR [gRegisterGeneral+112], r14
    mov QWORD PTR [gRegisterGeneral+120], r15
    setc al
    setp cl
    setz dl
    sets bl
    seto BYTE PTR [gRegisterFlags]
    movzx eax, al
    movzx ecx, cl
    shl ecx, 2
    or eax, ecx
    movzx ecx, dl
    shl ecx, 6
    or eax, ecx
    movzx ecx, bl
    shl ecx, 7
    or eax, ecx
    movzx ecx, BYTE PTR [gRegisterFlags]
    shl ecx, 11
    or eax, ecx
    mov QWORD PTR [gRegisterFlags], rax
    stmxcsr DWORD PTR [gRegisterMxCsr]
    movdqu XMMWORD PTR [gRegisterXmm+0], xmm0
    movdqu XMMWORD PTR [gRegisterXmm+16], xmm1
    movdqu XMMWORD PTR [gRegisterXmm+32], xmm2
    movdqu XMMWORD PTR [gRegisterXmm+48], xmm3
    movdqu XMMWORD PTR [gRegisterXmm+64], xmm4
    movdqu XMMWORD PTR [gRegisterXmm+80], xmm5
    movdqu XMMWORD PTR [gRegisterXmm+96], xmm6
    movdqu XMMWORD PTR [gRegisterXmm+112], xmm7
    movdqu XMMWORD PTR [gRegisterXmm+128], xmm8
    movdqu XMMWORD PTR [gRegisterXmm+144], xmm9
    movdqu XMMWORD PTR [gRegisterXmm+160], xmm10
    movdqu XMMWORD PTR [gRegisterXmm+176], xmm11
    movdqu XMMWORD PTR [gRegisterXmm+192], xmm12
    movdqu XMMWORD PTR [gRegisterXmm+208], xmm13
    movdqu XMMWORD PTR [gRegisterXmm+224], xmm14
    movdqu XMMWORD PTR [gRegisterXmm+240], xmm15
    cmp DWORD PTR [gRegisterAvxAvailable], 0
    je capture_complete
    vmovdqu YMMWORD PTR [gRegisterYmm+0], ymm0
    vmovdqu YMMWORD PTR [gRegisterYmm+32], ymm1
    vmovdqu YMMWORD PTR [gRegisterYmm+64], ymm2
    vmovdqu YMMWORD PTR [gRegisterYmm+96], ymm3
    vmovdqu YMMWORD PTR [gRegisterYmm+128], ymm4
    vmovdqu YMMWORD PTR [gRegisterYmm+160], ymm5
    vmovdqu YMMWORD PTR [gRegisterYmm+192], ymm6
    vmovdqu YMMWORD PTR [gRegisterYmm+224], ymm7
    vmovdqu YMMWORD PTR [gRegisterYmm+256], ymm8
    vmovdqu YMMWORD PTR [gRegisterYmm+288], ymm9
    vmovdqu YMMWORD PTR [gRegisterYmm+320], ymm10
    vmovdqu YMMWORD PTR [gRegisterYmm+352], ymm11
    vmovdqu YMMWORD PTR [gRegisterYmm+384], ymm12
    vmovdqu YMMWORD PTR [gRegisterYmm+416], ymm13
    vmovdqu YMMWORD PTR [gRegisterYmm+448], ymm14
    vmovdqu YMMWORD PTR [gRegisterYmm+480], ymm15
capture_complete:
    mov DWORD PTR [gRegisterPhase], 2
    fxrstor [rsp]
    add rsp, 520
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
RegisterProbe ENDP
END
