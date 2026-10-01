.686p
.xmm
.model flat, C
option casemap:none
EXTERN gRegisterAvxAvailable:DWORD
EXTERN gRegisterPhase:DWORD
EXTERN gRegisterStack:DWORD
EXTERN gRegisterGeneral:DWORD
EXTERN gRegisterFlags:DWORD
EXTERN gRegisterMxCsr:DWORD
EXTERN gRegisterMxCsrInput:DWORD
EXTERN gRegisterSeed:BYTE
EXTERN gRegisterXmm:BYTE
EXTERN gRegisterYmm:BYTE
PUBLIC RegisterProbe
PUBLIC RegisterStop
.code
RegisterProbe PROC
    push ebx
    push ebp
    push esi
    push edi
    mov eax, esp
    sub esp, 528
    and esp, -16
    mov DWORD PTR [esp+512], eax
    fxsave [esp]
    mov DWORD PTR [gRegisterStack], esp
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
registers_ready:
    xor eax, eax
    stc
    mov eax, 011223300h
    mov ebx, 011223301h
    mov ecx, 011223302h
    mov edx, 011223303h
    mov esi, 011223304h
    mov edi, 011223305h
    mov ebp, 011223306h
RegisterStop LABEL NEAR
    nop
    mov DWORD PTR [gRegisterGeneral+0], eax
    mov DWORD PTR [gRegisterGeneral+4], ebx
    mov DWORD PTR [gRegisterGeneral+8], ecx
    mov DWORD PTR [gRegisterGeneral+12], edx
    mov DWORD PTR [gRegisterGeneral+16], esi
    mov DWORD PTR [gRegisterGeneral+20], edi
    mov DWORD PTR [gRegisterGeneral+24], ebp
    mov DWORD PTR [gRegisterGeneral+28], esp
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
    mov DWORD PTR [gRegisterFlags], eax
    stmxcsr DWORD PTR [gRegisterMxCsr]
    movdqu XMMWORD PTR [gRegisterXmm+0], xmm0
    movdqu XMMWORD PTR [gRegisterXmm+16], xmm1
    movdqu XMMWORD PTR [gRegisterXmm+32], xmm2
    movdqu XMMWORD PTR [gRegisterXmm+48], xmm3
    movdqu XMMWORD PTR [gRegisterXmm+64], xmm4
    movdqu XMMWORD PTR [gRegisterXmm+80], xmm5
    movdqu XMMWORD PTR [gRegisterXmm+96], xmm6
    movdqu XMMWORD PTR [gRegisterXmm+112], xmm7
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
capture_complete:
    mov DWORD PTR [gRegisterPhase], 2
    fxrstor [esp]
    mov esp, DWORD PTR [esp+512]
    pop edi
    pop esi
    pop ebp
    pop ebx
    ret
RegisterProbe ENDP
END
