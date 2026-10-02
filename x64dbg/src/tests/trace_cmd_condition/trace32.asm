.686p
.model flat, C
option casemap:none
EXTERN gTraceSeed:DWORD
EXTERN gTraceValues:DWORD
EXTERN gTraceSum:DWORD
EXTERN gTraceCalls:DWORD
EXTERN gTraceEven:DWORD
EXTERN gTraceOdd:DWORD
EXTERN gTraceCompleted:DWORD
PUBLIC TraceRun
PUBLIC TraceBody
PUBLIC TraceLoop
PUBLIC TraceCall
PUBLIC TraceAfterCall
PUBLIC TraceAfterLoop
PUBLIC TraceDone
PUBLIC TraceLeaf
PUBLIC TraceOdd
.code
TraceRun PROC
TraceBody LABEL NEAR
    xor ecx, ecx
    xor edx, edx
    mov eax, DWORD PTR [gTraceSeed]
TraceLoop LABEL NEAR
    mov DWORD PTR [esp-4], 11223344h
TraceCall LABEL NEAR
    call TraceLeaf
TraceAfterCall LABEL NEAR
    mov DWORD PTR [gTraceValues+ecx*4], eax
    add edx, eax
    inc ecx
    cmp ecx, 4
    jne TraceLoop
TraceAfterLoop LABEL NEAR
    mov DWORD PTR [gTraceSum], edx
    mov DWORD PTR [gTraceCompleted], 1
TraceDone LABEL NEAR
    nop
    ret
TraceRun ENDP
TraceLeaf PROC
    inc DWORD PTR [gTraceCalls]
    test ecx, 1
    jnz TraceOdd
    add eax, 2
    inc DWORD PTR [gTraceEven]
    ret
TraceOdd LABEL NEAR
    add eax, 3
    inc DWORD PTR [gTraceOdd]
    ret
TraceLeaf ENDP
END
