option casemap:none
PUBLIC PatchCall
PUBLIC PatchAfterCall
PUBLIC PatchValue
PUBLIC PatchValueEnd
.code
PatchCall PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    xor eax, eax
    call PatchValue
PatchAfterCall LABEL NEAR
    add rsp, 40
    ret
PatchCall ENDP
PCAN SEGMENT ALIGN(4096) 'CODE'
PatchValue PROC
    mov eax, 7
    ret
PatchValueEnd LABEL NEAR
PatchValue ENDP
PCAN ENDS
END
