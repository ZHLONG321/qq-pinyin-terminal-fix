option casemap:none
EXTERN ResolveImeExport:PROC
.code

; 保存 x64 参数寄存器和原调用者的栈，再跳到原函数。
dispatch PROC FRAME
    sub rsp, 0a8h
    .allocstack 0a8h
    .endprolog
    mov [rsp+20h], rcx
    mov [rsp+28h], rdx
    mov [rsp+30h], r8
    mov [rsp+38h], r9
    movdqu [rsp+40h], xmm0
    movdqu [rsp+50h], xmm1
    movdqu [rsp+60h], xmm2
    movdqu [rsp+70h], xmm3
    mov ecx, r10d
    call ResolveImeExport
    mov r11, rax
    mov rcx, [rsp+20h]
    mov rdx, [rsp+28h]
    mov r8, [rsp+30h]
    mov r9, [rsp+38h]
    movdqu xmm0, [rsp+40h]
    movdqu xmm1, [rsp+50h]
    movdqu xmm2, [rsp+60h]
    movdqu xmm3, [rsp+70h]
    add rsp, 0a8h
    jmp r11
dispatch ENDP

forward MACRO symbol:req, number:req
    PUBLIC symbol
    symbol PROC
        mov r10d, number
        jmp dispatch
    symbol ENDP
ENDM

forward ImeFreeEnv, 0
forward ImeGetEnv, 1
forward ImeSetCompositionString, 2
forward ImeConfigure, 3
forward ImeConversionList, 4
forward ImeDestroy, 5
forward ImeEnumRegisterWord, 6
forward ImeEscape, 7
forward ImeExtension, 8
forward ImeGetRegisterWordStyle, 9
forward ImeInquire, 10
forward ImeProcessKey, 11
forward ImeRegisterWord, 12
forward ImeSelect, 13
forward ImeSetActiveContext, 14
forward ImeToAsciiEx, 15
forward ImeUnregisterWord, 16
forward NotifyIME, 17
END
