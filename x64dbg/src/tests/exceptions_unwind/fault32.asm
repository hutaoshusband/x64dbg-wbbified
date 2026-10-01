.686p
.xmm
.model flat, C
option casemap:none
EXTERN ExceptionHandled:PROC
EXTERN gExceptionFaultStack:DWORD
EXTERN gExceptionWrapperStack:DWORD
EXTERN gExceptionAfterStack:DWORD
EXTERN gExceptionAfterGeneral:DWORD
EXTERN gExceptionFaultSeed:BYTE
EXTERN gExceptionInstructionValue:DWORD
EXTERN gExceptionAfterProbe:DWORD
EXTERN gExceptionWrapperCompleted:DWORD
EXTERN gExceptionProbeReturn:DWORD
PUBLIC ExceptionRun
PUBLIC ExceptionProbe
PUBLIC ExceptionFault
PUBLIC ExceptionAfterFault
PUBLIC ExceptionAfterHandled
.code
ExceptionRun PROC
    push ebx
    push esi
    sub esp, 32
    mov DWORD PTR [gExceptionWrapperStack], esp
    mov ebx, 55667788h
    mov esi, 44332211h
    call ExceptionHandled
ExceptionAfterHandled LABEL NEAR
    mov DWORD PTR [gExceptionAfterGeneral], ebx
    mov DWORD PTR [gExceptionAfterGeneral+4], esi
    mov DWORD PTR [gExceptionAfterStack], esp
    mov DWORD PTR [gExceptionWrapperCompleted], 1
    add esp, 32
    pop esi
    pop ebx
    ret
ExceptionRun ENDP
ExceptionProbe PROC
    push ebp
    mov ebp, esp
    sub esp, 8
    mov DWORD PTR [gExceptionFaultStack], esp
    mov eax, DWORD PTR [ebp+4]
    mov DWORD PTR [gExceptionProbeReturn], eax
    movdqu xmm6, XMMWORD PTR [gExceptionFaultSeed]
    mov eax, 11223344h
ExceptionFault LABEL NEAR
    ud2
ExceptionAfterFault LABEL NEAR
    mov DWORD PTR [gExceptionInstructionValue], eax
    inc DWORD PTR [gExceptionAfterProbe]
    mov esp, ebp
    pop ebp
    ret
ExceptionProbe ENDP
END
