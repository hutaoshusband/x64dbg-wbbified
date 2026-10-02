.686p
.model flat, C
option casemap:none
PUBLIC PatchCall
PUBLIC PatchAfterCall
PUBLIC PatchValue
PUBLIC PatchValueEnd
.code
PatchCall PROC
    xor eax, eax
    call PatchValue
PatchAfterCall LABEL NEAR
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
