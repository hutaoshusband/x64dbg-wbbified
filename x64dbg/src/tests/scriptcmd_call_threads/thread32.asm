.686p
.model flat, C
option casemap:none
EXTERN gThreadValues:DWORD
PUBLIC ThreadProbe0
PUBLIC ThreadProbe1
PUBLIC ThreadStop0
PUBLIC ThreadStop1
.code
ThreadProbe0 PROC
    mov eax, 10203040h
ThreadStop0 LABEL NEAR
    nop
    mov DWORD PTR [gThreadValues], eax
    ret
ThreadProbe0 ENDP
ThreadProbe1 PROC
    mov eax, 50607080h
ThreadStop1 LABEL NEAR
    nop
    mov DWORD PTR [gThreadValues+4], eax
    ret
ThreadProbe1 ENDP
END
