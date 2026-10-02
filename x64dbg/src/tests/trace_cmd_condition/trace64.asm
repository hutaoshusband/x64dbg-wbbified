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
TraceRun PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
TraceBody LABEL NEAR
    xor ecx, ecx
    xor edx, edx
    lea r8, gTraceValues
    mov eax, DWORD PTR [gTraceSeed]
TraceLoop LABEL NEAR
    mov QWORD PTR [rsp-8], 11223344h
TraceCall LABEL NEAR
    call TraceLeaf
TraceAfterCall LABEL NEAR
    mov DWORD PTR [r8+rcx*4], eax
    add edx, eax
    inc ecx
    cmp ecx, 4
    jne TraceLoop
TraceAfterLoop LABEL NEAR
    mov DWORD PTR [gTraceSum], edx
    mov DWORD PTR [gTraceCompleted], 1
TraceDone LABEL NEAR
    nop
    add rsp, 40
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
