/* Des encryption in GNU assebler version for i386 processors. 

   Author Mika Kojo <mkojo@ssh.fi>	
   Copyright:
           Copyright (c) 2002, 2003 SFNT Finland Oy.
   All rights reserved.

   This code is derived from the fast C-language DES implementation by
   Eric Young. 
	
   Few minor modifications were made to allow more optimized code. 

   This code has been timed to run > 12 MBits/sec with SSH Crypto Library on
   Pentium 133Mhz. (Without the overhead 16.2 MBits/sec)
		
   */

	.file "des386.S"
	.text

#include "sshconf.h"
/* Define the C names. We need the check for underscores due some 
   differences in platforms. E.g. Linux and FreeBSD are different on 
   this account. */
#ifdef HAVE_NO_SYMBOL_UNDERSCORE
#define DES_SP_TRANS     ssh_des_SPtrans
#define DES_ENCRYPT      ssh_des_encrypt
#define DES_EDE_ENCRYPT  ssh_des_ede_encrypt
#else
#define DES_SP_TRANS     _ssh_des_SPtrans	
#define DES_ENCRYPT      _ssh_des_encrypt
#define DES_EDE_ENCRYPT  _ssh_des_ede_encrypt
#endif
	
		.align 2
    	.globl DES_ENCRYPT
		.type DES_ENCRYPT, @function
	
DES_ENCRYPT:
	
	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi
	
#define XL  8(%ebp)
#define XR  12(%ebp)
#define OUTPUT 16(%ebp)
#define CTX 20(%ebp)
#define ENCRYPT 24(%ebp)
	
	movl CTX, %edi

	movl XL, %eax
	movl XR, %ebx

       	/* Clear index here */
	xorl %ecx, %ecx
	xorl %edx, %edx

#define PERM_OP(a,b,t,n,m) \
	movl a, t; \
	shrl n, t; \
	xorl b, t; \
	andl m, t; \
	xorl t, b; \
	shll n, t; \
	xorl t, a;

#define IP(l,r,t) \
	PERM_OP(r,l,t, $4,$0x0f0f0f0f); \
	PERM_OP(l,r,t,$16,$0x0000ffff); \
	PERM_OP(r,l,t, $2,$0x33333333); \
	PERM_OP(l,r,t, $8,$0x00ff00ff); \
	PERM_OP(r,l,t, $1,$0x55555555);

#define FP(l,r,t) \
	PERM_OP(l,r,t, $1,$0x55555555); \
	PERM_OP(r,l,t, $8,$0x00ff00ff); \
	PERM_OP(l,r,t, $2,$0x33333333); \
	PERM_OP(r,l,t,$16,$0x0000ffff); \
	PERM_OP(l,r,t, $4,$0x0f0f0f0f);

	/* D_ENCRYPT 

On entry:
	ebx = R
	esi = L

On exit:
	ebx = L
	esi = R
		
	This is somewhat optimized version, but there is quite a lot of
	possibilities to do as the D_ENCRYPT later will show you. */

#define D_ENCRYPT_OLD(n) \
       	movl %ebx, %eax;                \
	pushl %ebx;                     \
	xorl ((n+1)*4)(%edi), %eax;     \
	xorl (n*4)(%edi), %ebx;         \
        rorl $4, %eax;                  \
					\
	andl $0x3f3f3f3f, %ebx;         \
	andl $0x3f3f3f3f, %eax;         \
		                        \
      	movb %bl, %cl;                  \
	movb %al, %dl;                  \
      	xorl (0*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
	movl (1*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
                                        \
	movb %bh, %cl;                  \
	movb %ah, %dl;                  \
      	roll $16, %ebx;                 \
       	xorl (2*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
      	xorl (3*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
      	roll $16, %eax;                 \
	                                \
	movb %bl, %cl;                  \
	movb %al, %dl;                  \
       	xorl (4*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
       	xorl (5*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
                                        \
	movb %bh, %cl;                  \
	movb %ah, %dl;                  \
       	xorl (6*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
      	xorl (7*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
                                        \
	xorl %ebp, %esi;                \
        movl %esi, %ebx;                \
	popl %esi; 

	
	/* This version is not as simple to use but should be
	faster.

On entry:
	esi ^ ebp = R
	in stack = L

On exit:
	esi ^ ebp = L
	in stack = R
	
	*/
	
#define D_ENCRYPT(n) \
	movl ((n+1)*4)(%edi), %eax;     /* key[n+1] = eax   */ \
      	xorl %esi, %ebp;                /* ebp^esi = L      */ \
					\
	movl (n*4)(%edi), %ebx;         /* key[n]   = ebx   */ \
	xorl %ebp, %eax;                /* eax ^ L  = eax   */ \
					\
      	popl %esi;                      /* stack = esi = R  */ \
	xorl %ebp, %ebx;                /* ebx ^ L  = ebx   */ \
					\
     	rorl $4, %eax;                  /* ror eax by 4     */ \
	andl $0x3f3f3f3f, %ebx;         \
	andl $0x3f3f3f3f, %eax;         \
		                        \
	movb %bl, %cl;                  \
	movb %al, %dl;                  \
      	pushl %ebp;                     /* stack ebp = L    */ \
					\
      	xorl (0*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
	movl (1*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
                                        \
	movb %bh, %cl;                  \
	movb %ah, %dl;                  \
      	roll $16, %ebx;                 \
       	xorl (2*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
      	xorl (3*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
      	roll $16, %eax;                 \
	                                \
	movb %bl, %cl;                  \
	movb %al, %dl;                  \
       	xorl (4*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
       	xorl (5*64*4+DES_SP_TRANS)(, %edx, 4), %ebp; \
                                        \
	movb %bh, %cl;                  \
	movb %ah, %dl;                  \
       	xorl (6*64*4+DES_SP_TRANS)(, %ecx, 4), %esi; \
      	xorl (7*64*4+DES_SP_TRANS)(, %edx, 4), %ebp;

     	IP(%eax, %ebx, %esi) 
	
	roll $1, %ebx
	roll $1, %eax

	/* Check for encrypt/decrypt flag */
       	cmpl $0, ENCRYPT
	jz des_encrypt_is_to_decrypt

       	/* We need ebp in innerloops */
	pushl %ebp

	/* Set input for D_ENCRYPT (eax = L and ebx = R to stack and esi) */
	pushl %ebx
	movl %eax, %esi
	xorl %ebp, %ebp
	/* Encryption */

	D_ENCRYPT(0)
      	D_ENCRYPT(2)
			
	D_ENCRYPT(4)
	D_ENCRYPT(6)

	D_ENCRYPT(8)
	D_ENCRYPT(10)

	D_ENCRYPT(12)
	D_ENCRYPT(14)
		
	
	D_ENCRYPT(16)
	D_ENCRYPT(18)
	
	D_ENCRYPT(20)
	D_ENCRYPT(22)

	D_ENCRYPT(24)
	D_ENCRYPT(26)

	D_ENCRYPT(28)
	D_ENCRYPT(30)

	jmp des_finish_des_encrypt

des_encrypt_is_to_decrypt:	

       	/* We need ebp in innerloops */
	pushl %ebp

	/* Set input for D_ENCRYPT */
	pushl %ebx
	movl %eax, %esi
	xorl %ebp, %ebp
	
	/* Decryption */
	
	D_ENCRYPT(30)
	D_ENCRYPT(28)
	
	D_ENCRYPT(26)
	D_ENCRYPT(24)

	D_ENCRYPT(22)
	D_ENCRYPT(20)

	D_ENCRYPT(18)
	D_ENCRYPT(16)
		
	
	D_ENCRYPT(14)
	D_ENCRYPT(12)
	
	D_ENCRYPT(10)
	D_ENCRYPT(8)

	D_ENCRYPT(6)
	D_ENCRYPT(4)

	D_ENCRYPT(2)
	D_ENCRYPT(0)

des_finish_des_encrypt:	

	/* Get the answer */
	xorl %ebp, %esi
	popl %eax 

	/* Get the stack pointer */
	popl %ebp
			
	/* Substitute esi by ebx */
	movl %esi, %ebx
		
	rorl $1, %eax
	rorl $1, %ebx

      	FP(%ebx, %eax, %edx) 

	movl OUTPUT, %esi
	
	movl %eax, (%esi)
	movl %ebx, 4(%esi)

	/* Clear stack */

	popl %edi
	popl %esi
	popl %ebx

	movl %ebp, %esp
	popl %ebp
	ret

/*
	Triple DES encryption (encrypt/decrypt/encrypt)
	
	*/
	
		.align 2
    	.globl DES_EDE_ENCRYPT
		.type DES_EDE_ENCRYPT, @function
	
DES_EDE_ENCRYPT:		
	
	pushl %ebp
	movl %esp, %ebp

	pushl %ebx
	pushl %esi
	pushl %edi
	
	movl CTX, %edi

	movl XL, %eax
	movl XR, %ebx

       	/* Clear index here */
	xorl %ecx, %ecx
	xorl %edx, %edx
	
     	IP(%eax, %ebx, %esi) 
	
	roll $1, %ebx
	roll $1, %eax

	/* Check for encrypt/decrypt flag */
       	cmpl $0, ENCRYPT
	jz des3_encrypt_is_to_decrypt

       	/* We need ebp in innerloops */
	pushl %ebp

	/* Set input for D_ENCRYPT (eax = L and ebx = R to stack and esi) */
	pushl %ebx
	movl %eax, %esi
	xorl %ebp, %ebp
	/* Encryption */

	D_ENCRYPT(0)
      	D_ENCRYPT(2)
			
	D_ENCRYPT(4)
	D_ENCRYPT(6)

	D_ENCRYPT(8)
	D_ENCRYPT(10)

	D_ENCRYPT(12)
	D_ENCRYPT(14)
		
	
	D_ENCRYPT(16)
	D_ENCRYPT(18)
	
	D_ENCRYPT(20)
	D_ENCRYPT(22)

	D_ENCRYPT(24)
	D_ENCRYPT(26)

	D_ENCRYPT(28)
	D_ENCRYPT(30)

	/* Swap for decryption. */

	popl %ebx
	xorl %ebp, %esi
	push %esi
	movl %ebx, %esi
	xorl %ebp, %ebp
	
       	/* Decryption */
	
	D_ENCRYPT(62)
      	D_ENCRYPT(60)
			
	D_ENCRYPT(58)
	D_ENCRYPT(56)

	D_ENCRYPT(54)
	D_ENCRYPT(52)

	D_ENCRYPT(50)
	D_ENCRYPT(48)
		
	
	D_ENCRYPT(46)
	D_ENCRYPT(44)
	
	D_ENCRYPT(42)
	D_ENCRYPT(40)

	D_ENCRYPT(38)
	D_ENCRYPT(36)

	D_ENCRYPT(34)
	D_ENCRYPT(32)

	/* Swap for encryption. */
	popl %ebx
	xorl %ebp, %esi
	push %esi
	movl %ebx, %esi
	xorl %ebp, %ebp
	
	/* Encryption */

	D_ENCRYPT(64)
      	D_ENCRYPT(66)
			
	D_ENCRYPT(68)
	D_ENCRYPT(70)

	D_ENCRYPT(72)
	D_ENCRYPT(74)

	D_ENCRYPT(76)
	D_ENCRYPT(78)
		
	
	D_ENCRYPT(80)
	D_ENCRYPT(82)
	
	D_ENCRYPT(84)
	D_ENCRYPT(86)

	D_ENCRYPT(88)
	D_ENCRYPT(90)

	D_ENCRYPT(92)
	D_ENCRYPT(94)

	jmp des3_finish_des_encrypt

des3_encrypt_is_to_decrypt:	

       	/* We need ebp in innerloops */
	pushl %ebp

	/* Set input for D_ENCRYPT */
	pushl %ebx
	movl %eax, %esi
	xorl %ebp, %ebp
	
	/* Decryption */
	
	D_ENCRYPT(94)
	D_ENCRYPT(92)
	
	D_ENCRYPT(90)
	D_ENCRYPT(88)

	D_ENCRYPT(86)
	D_ENCRYPT(84)

	D_ENCRYPT(82)
	D_ENCRYPT(80)
		
	
	D_ENCRYPT(78)
	D_ENCRYPT(76)
	
	D_ENCRYPT(74)
	D_ENCRYPT(72)

	D_ENCRYPT(70)
	D_ENCRYPT(68)

	D_ENCRYPT(66)
	D_ENCRYPT(64)

	/* Swap for encryption. */
	
	popl %ebx
	xorl %ebp, %esi
	push %esi
	movl %ebx, %esi
	xorl %ebp, %ebp
	
	/* Encryption */
	
	D_ENCRYPT(32)
	D_ENCRYPT(34)
	
	D_ENCRYPT(36)
	D_ENCRYPT(38)

	D_ENCRYPT(40)
	D_ENCRYPT(42)

	D_ENCRYPT(44)
	D_ENCRYPT(46)
		
	
	D_ENCRYPT(48)
	D_ENCRYPT(50)
	
	D_ENCRYPT(52)
	D_ENCRYPT(54)

	D_ENCRYPT(56)
	D_ENCRYPT(58)

	D_ENCRYPT(60)
	D_ENCRYPT(62)

	/* Swap for decryption. */
	popl %ebx
	xorl %ebp, %esi
	push %esi
	movl %ebx, %esi
	xorl %ebp, %ebp
	
	/* Decryption */
	
	D_ENCRYPT(30)
	D_ENCRYPT(28)
	
	D_ENCRYPT(26)
	D_ENCRYPT(24)

	D_ENCRYPT(22)
	D_ENCRYPT(20)

	D_ENCRYPT(18)
	D_ENCRYPT(16)
		
	
	D_ENCRYPT(14)
	D_ENCRYPT(12)
	
	D_ENCRYPT(10)
	D_ENCRYPT(8)

	D_ENCRYPT(6)
	D_ENCRYPT(4)

	D_ENCRYPT(2)
	D_ENCRYPT(0)

des3_finish_des_encrypt:	

	/* Get the answer */
	xorl %ebp, %esi
	popl %eax 

	/* Get the stack pointer */
	popl %ebp
			
	/* Substitute esi by ebx */
	movl %esi, %ebx
		
	rorl $1, %eax
	rorl $1, %ebx

      	FP(%ebx, %eax, %edx) 

	movl OUTPUT, %esi
		
	movl %eax, (%esi)
	movl %ebx, 4(%esi)

	/* Clear stack */

	popl %edi
	popl %esi
	popl %ebx

	movl %ebp, %esp
	popl %ebp
	ret

/* Make the des_SPtrans visible to assembler from the des.c module */
/* .comm DES_SP_TRANS, 2048 */
		
#undef D_ENCRYPT


