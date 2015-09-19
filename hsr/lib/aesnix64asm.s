[bits 64]
[CPU intelnop]

%macro linux_setup 0
%ifdef __linux__
 	mov r9, rcx
 	mov r8, rdx
	mov rcx, rdi
	mov rdx, rsi
%endif
%endmacro

%macro inversekey 1
	movdqu  xmm1,%1
	aesimc	xmm0,xmm1
	movdqu	%1,xmm0
%endmacro

%macro aesenc1_u 1
	movdqu	xmm4,%1
	aesenc	xmm0,xmm4
%endmacro

%macro aesenclast1_u 1
	movdqu	xmm4,%1
	aesenclast	xmm0,xmm4
%endmacro

%macro aesenc2_u 1
	movdqu	xmm4,%1
	aesenc	xmm0,xmm4
	aesenc	xmm1,xmm4
%endmacro

%macro aesenclast2_u 1
	movdqu	xmm4,%1
	aesenclast	xmm0,xmm4
	aesenclast	xmm1,xmm4
%endmacro

%macro aesenc4 1
	movdqa	xmm4,%1
	
	aesenc	xmm0,xmm4
	aesenc	xmm1,xmm4
	aesenc	xmm2,xmm4
	aesenc	xmm3,xmm4
%endmacro

%macro aesenclast4 1
	movdqa	xmm4,%1
	;movdqa	xmm5,xmm4
	;movdqa	xmm6,xmm4
	;movdqa	xmm7,xmm4

	aesenclast	xmm0,xmm4
	aesenclast	xmm1,xmm4
	aesenclast	xmm2,xmm4
	aesenclast	xmm3,xmm4
%endmacro

%macro load_and_inc4 1
	movdqa	xmm4,%1
	movdqa	xmm0,xmm5
	pshufb	xmm0, xmm6 ; byte swap counter back
	movdqa  xmm1,xmm5
	paddd	xmm1,[counter_add_one wrt rip]
	pshufb	xmm1, xmm6 ; byte swap counter back
	movdqa  xmm2,xmm5
	paddd	xmm2,[counter_add_two wrt rip]
	pshufb	xmm2, xmm6 ; byte swap counter back
	movdqa  xmm3,xmm5
	paddd	xmm3,[counter_add_three wrt rip]
	pshufb	xmm3, xmm6 ; byte swap counter back
	pxor	xmm0,xmm4
	paddd	xmm5,[counter_add_four wrt rip]
	pxor	xmm1,xmm4
	pxor	xmm2,xmm4
	pxor	xmm3,xmm4
%endmacro

%macro xor_with_input4 1
	movdqu xmm4,[%1]
	pxor xmm0,xmm4
	movdqu xmm4,[%1+16]
	pxor xmm1,xmm4
	movdqu xmm4,[%1+32]
	pxor xmm2,xmm4
	movdqu xmm4,[%1+48]
	pxor xmm3,xmm4
%endmacro

%macro load_and_xor4 2
	movdqa	xmm4,%2
	movdqu	xmm0,[%1 + 0*16]
	pxor	xmm0,xmm4
	movdqu	xmm1,[%1 + 1*16]
	pxor	xmm1,xmm4
	movdqu	xmm2,[%1 + 2*16]
	pxor	xmm2,xmm4
	movdqu	xmm3,[%1 + 3*16]
	pxor	xmm3,xmm4
%endmacro

%macro store4 1
	movdqu [%1 + 0*16],xmm0
	movdqu [%1 + 1*16],xmm1
	movdqu [%1 + 2*16],xmm2
	movdqu [%1 + 3*16],xmm3
%endmacro

%macro copy_round_keys 3
	movdqu xmm4,[%2 + ((%3)*16)]
	movdqa [%1 + ((%3)*16)],xmm4
%endmacro


%macro key_expansion_1_192 1
	;; Assumes the xmm3 includes all zeros at this point. 
    pshufd xmm2, xmm2, 11111111b        
    shufps xmm3, xmm1, 00010000b        
    pxor xmm1, xmm3        
    shufps xmm3, xmm1, 10001100b
    pxor xmm1, xmm3        
	pxor xmm1, xmm2		
	movdqu [rdx+%1], xmm1			
%endmacro

; Calculate w10 and w11 using calculated w9 and known w4-w5
%macro key_expansion_2_192 1				
	movdqa xmm5, xmm4
	pslldq xmm5, 4
	shufps xmm6, xmm1, 11110000b
	pxor xmm6, xmm5
	pxor xmm4, xmm6
	pshufd xmm7, xmm4, 00001110b 
	movdqu [rdx+%1], xmm7
%endmacro


section .data
align 16
shuffle_mask:
DD 0FFFFFFFFh
DD 03020100h
DD 07060504h
DD 0B0A0908h

byte_swap_16:
DDQ 0x000102030405060708090A0B0C0D0E0F


align 16
counter_add_one:
DD 1
DD 0
DD 0
DD 0

counter_add_two:
DD 2
DD 0
DD 0
DD 0

counter_add_three:
DD 3
DD 0
DD 0
DD 0

counter_add_four:
DD 4
DD 0
DD 0
DD 0



section .text

align 16
key_expansion128: 
    pshufd xmm2, xmm2, 0xFF;
    movdqa xmm3, xmm1
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pshufb xmm3, xmm5
    pxor xmm1, xmm3
    pxor xmm1, xmm2

    ; storing the result in the key schedule array
    movdqu [rdx], xmm1
    add rdx, 0x10                    
    ret
    

align 16
global ExpandKey128
ExpandKey128:

	linux_setup

    movdqu xmm1, [rcx]    ; loading the key

    movdqu [rdx], xmm1

    movdqa xmm5, [shuffle_mask wrt rip]

    add rdx,16

    aeskeygenassist xmm2, xmm1, 0x1     ; Generating round key 1
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x2     ; Generating round key 2
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x4     ; Generating round key 3
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x8     ; Generating round key 4
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x10    ; Generating round key 5
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x20    ; Generating round key 6
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x40    ; Generating round key 7
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x80    ; Generating round key 8
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x1b    ; Generating round key 9
    call key_expansion128
    aeskeygenassist xmm2, xmm1, 0x36    ; Generating round key 10
    call key_expansion128

	ret


align 16
global CBCMAC1MULTI
CBCMAC1MULTI:
	
	linux_setup
	
	sub rsp,16*16+8
	
	test edx, edx			; if core id = 0
	jz case0
	
	dec  edx
	test edx, edx			; if core id = 1
	jz case1
	
	dec  edx
	test edx, edx			; if core id = 2
	jz case2
	
	dec  edx
	test edx, edx			; if core id = 3
	jz case3
	
	dec  edx
	test edx, edx			; if core id = 4
	jz case4
	
	dec  edx
	test edx, edx			; if core id = 5
	jz case5
	
	dec  edx
	test edx, edx			; if core id = 6
	jz case6
	
	dec  edx
	test edx, edx			; if core id = 7
	jz case7
	
	jmp end_op				; if core id is over boundary

case0:

	movdqu xmm0, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm1, [rdx]
	pxor xmm0, xmm1
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm1, [rcx+0*16]	; loading the round keys
	
	; aes encryption procedure
	pxor xmm0, xmm1
	movdqu	xmm1,[rcx+1*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+2*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+3*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+4*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+5*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+6*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+7*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+8*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+9*16]
	aesenc	xmm0,xmm1
	movdqu	xmm1,[rcx+10*16]
	aesenclast	xmm0,xmm1
	
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm0
	jmp end_op

case1:

	movdqu xmm2, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm3, [rdx]
	pxor xmm2, xmm3
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm3, [rcx+0*16]	; loading the round keys
	
	pxor xmm2, xmm3
	movdqu	xmm3,[rcx+1*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+2*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+3*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+4*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+5*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+6*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+7*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+8*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+9*16]
	aesenc	xmm2,xmm3
	movdqu	xmm3,[rcx+10*16]
	aesenclast	xmm2,xmm3
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm2
	jmp end_op

case2:

	movdqu xmm4, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm5, [rdx]
	pxor xmm4, xmm5
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm5, [rcx+0*16]	; loading the round keys
	
	pxor xmm4, xmm5
	
	movdqu	xmm5,[rcx+1*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+2*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+3*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+4*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+5*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+6*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+7*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+8*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+9*16]
	aesenc	xmm4,xmm5
	movdqu	xmm5,[rcx+10*16]
	aesenclast	xmm4,xmm5
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm4
	jmp end_op

case3:

	movdqu xmm6, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm7, [rdx]
	pxor xmm6, xmm7
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm7, [rcx+0*16]	; loading the round keys
	
	pxor xmm6, xmm7
	
	movdqu	xmm7,[rcx+1*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+2*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+3*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+4*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+5*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+6*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+7*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+8*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+9*16]
	aesenc	xmm6,xmm7
	movdqu	xmm7,[rcx+10*16]
	aesenclast	xmm6,xmm7
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm6
	jmp end_op

case4:

	movdqu xmm8, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm9, [rdx]
	pxor xmm8, xmm9
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm9, [rcx+0*16]	; loading the round keys
	
	pxor xmm8, xmm9
	
	movdqu	xmm9,[rcx+1*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+2*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+3*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+4*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+5*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+6*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+7*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+8*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+9*16]
	aesenc	xmm8,xmm9
	movdqu	xmm9,[rcx+10*16]
	aesenclast	xmm8,xmm9
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm8
	jmp end_op

case5:

	movdqu xmm10, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm11, [rdx]
	pxor xmm10, xmm11
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm11, [rcx+0*16]	; loading the round keys
	
	pxor xmm10, xmm11
	
	movdqu	xmm11,[rcx+1*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+2*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+3*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+4*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+5*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+6*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+7*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+8*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+9*16]
	aesenc	xmm10,xmm11
	movdqu	xmm11,[rcx+10*16]
	aesenclast	xmm10,xmm11
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm10
	jmp end_op

case6:

	movdqu xmm12, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm13, [rdx]
	pxor xmm12, xmm13
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm13, [rcx+0*16]	; loading the round keys
	
	pxor xmm12, xmm13
	
	movdqu	xmm13,[rcx+1*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+2*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+3*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+4*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+5*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+6*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+7*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+8*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+9*16]
	aesenc	xmm12,xmm13
	movdqu	xmm13,[rcx+10*16]
	aesenclast	xmm12,xmm13
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm12
	jmp end_op

case7:

	movdqu xmm14, [r8]		; loading the input
	mov rdx, [rcx]			; loading the iv
	movdqu xmm15, [rdx]
	pxor xmm14, xmm15
	
	mov rcx, [rcx+8]		; loading the round keys
	movdqu xmm15, [rcx+0*16]	; loading the round keys
	
	pxor xmm14, xmm15
	
	movdqu	xmm15,[rcx+1*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+2*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+3*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+4*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+5*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+6*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+7*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+8*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+9*16]
	aesenc	xmm14,xmm15
	movdqu	xmm15,[rcx+10*16]
	aesenclast	xmm14,xmm15
	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm14

end_op:
	add rsp,16*16+8
	ret


align 16
global _do_rdtsc
_do_rdtsc:

	rdtsc
	ret

align 16
global CBCMAC1BLK
CBCMAC1BLK:
	
	linux_setup
	
	sub rsp,16*16+8

	movdqu xmm0, [r8]		; loading the input
	movdqu xmm1, [rdx]		; loading the mac
	movdqu xmm4, [rcx+0*16]	; loading the round keys
	
	;pxor xmm0, xmm1
	pxor xmm0, xmm4
	aesenc1_u [rcx+1*16]
	aesenc1_u [rcx+2*16]
	aesenc1_u [rcx+3*16]
	aesenc1_u [rcx+4*16]     
	aesenc1_u [rcx+5*16]
	aesenc1_u [rcx+6*16]
	aesenc1_u [rcx+7*16]
	aesenc1_u [rcx+8*16]
	aesenc1_u [rcx+9*16]
	aesenclast1_u [rcx+10*16]

	; Store output encrypted data into CIPHERTEXT array
	;movdqu xmm1, [rdx]
	add rsp,16*16+8
	pxor xmm0, xmm1
	movdqu  [r9], xmm0
	ret

align 16
global CBCMAC4BLK
CBCMAC4BLK:
	
	linux_setup
	
	sub rsp,16*16+8

	movdqu xmm0, [r8]		; loading the input1
	movdqu xmm1, [r8+16]	; loading the input2
	movdqu xmm2, [r8+32]	; loading the input3
	movdqu xmm3, [r8+48]	; loading the input4
	movdqu xmm5, [rdx]		; loading the iv
	movdqu xmm4, [rcx+0*16]	; loading the round keys
	
	pxor xmm0, xmm5
	pxor xmm0, xmm4
	
	pxor xmm1, xmm5
	pxor xmm1, xmm4
	
	pxor xmm2, xmm5
	pxor xmm2, xmm4
	
	pxor xmm3, xmm5
	pxor xmm3, xmm4
	
	aesenc4 [rcx+1*16]
	aesenc4 [rcx+2*16]
	aesenc4 [rcx+3*16]
	aesenc4 [rcx+4*16]     
	aesenc4 [rcx+5*16]
	aesenc4 [rcx+6*16]
	aesenc4 [rcx+7*16]
	aesenc4 [rcx+8*16]
	aesenc4 [rcx+9*16]
	aesenclast4 [rcx+10*16]

	; Store output encrypted data into CIPHERTEXT array
	movdqu  [r9], xmm0
	movdqu  [r9+16], xmm1
	movdqu  [r9+32], xmm2
	movdqu  [r9+48], xmm3
	add rsp,16*16+8
	ret
	
		


