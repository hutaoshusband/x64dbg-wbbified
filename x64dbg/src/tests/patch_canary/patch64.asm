option casemap:none
PUBLIC PatchCall
PUBLIC PatchAfterCall
PUBLIC PatchValue
PUBLIC PatchValueEnd
PUBLIC PatchRelocation
PUBLIC PatchVirtualTail
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
PREF SEGMENT ALIGN(4096) 'DATA'
PatchRelocation DQ PatchValue
PREF ENDS
PBSS SEGMENT ALIGN(4096) 'BSS'
PatchVirtualTail BYTE 8192 DUP(?)
PBSS ENDS
END
