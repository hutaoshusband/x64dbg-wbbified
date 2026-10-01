option casemap:none
EXTERN ExceptionHandled:PROC
EXTERN gExceptionFaultStack:QWORD
EXTERN gExceptionWrapperStack:QWORD
EXTERN gExceptionAfterStack:QWORD
EXTERN gExceptionAfterGeneral:QWORD
EXTERN gExceptionCallerSeed:BYTE
EXTERN gExceptionFaultSeed:BYTE
EXTERN gExceptionAfterXmm:BYTE
EXTERN gExceptionInstructionValue:DWORD
EXTERN gExceptionAfterProbe:DWORD
EXTERN gExceptionWrapperCompleted:DWORD
EXTERN gExceptionProbeReturn:QWORD
PUBLIC ExceptionRun
PUBLIC ExceptionProbe
PUBLIC ExceptionFault
PUBLIC ExceptionAfterFault
PUBLIC ExceptionAfterHandled
.code
ExceptionRun PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    sub rsp, 56
    .allocstack 56
    movdqu XMMWORD PTR [rsp+32], xmm6
    .savexmm128 xmm6, 32
    .endprolog
    mov QWORD PTR [gExceptionWrapperStack], rsp
    mov rbx, 01122334455667788h
    mov r12, 08877665544332211h
    movdqu xmm6, XMMWORD PTR [gExceptionCallerSeed]
    call ExceptionHandled
ExceptionAfterHandled LABEL NEAR
    mov QWORD PTR [gExceptionAfterGeneral], rbx
    mov QWORD PTR [gExceptionAfterGeneral+8], r12
    movdqu XMMWORD PTR [gExceptionAfterXmm], xmm6
    mov QWORD PTR [gExceptionAfterStack], rsp
    mov DWORD PTR [gExceptionWrapperCompleted], 1
    movdqu xmm6, XMMWORD PTR [rsp+32]
    add rsp, 56
    pop r12
    pop rbx
    ret
ExceptionRun ENDP
ExceptionProbe PROC FRAME
    push rbx
    .pushreg rbx
    push r12
    .pushreg r12
    sub rsp, 56
    .allocstack 56
    movdqu XMMWORD PTR [rsp+32], xmm6
    .savexmm128 xmm6, 32
    .endprolog
    mov QWORD PTR [gExceptionFaultStack], rsp
    mov rax, QWORD PTR [rsp+72]
    mov QWORD PTR [gExceptionProbeReturn], rax
    mov rbx, 02233445566778899h
    mov r12, 09988776655443322h
    movdqu xmm6, XMMWORD PTR [gExceptionFaultSeed]
    mov eax, 11223344h
ExceptionFault LABEL NEAR
    ud2
ExceptionAfterFault LABEL NEAR
    mov DWORD PTR [gExceptionInstructionValue], eax
    inc DWORD PTR [gExceptionAfterProbe]
    movdqu xmm6, XMMWORD PTR [rsp+32]
    add rsp, 56
    pop r12
    pop rbx
    ret
ExceptionProbe ENDP
END
