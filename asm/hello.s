
    .section .text
    .globl _start

_start:

    xorl    %eax,%eax
    pushq   %rax
    movb    $0x6f,0x4(%rsp)
    movl    $0x6c6c6548,(%rsp)
    xorl    %eax,%eax
    incl    %eax
    xorl    %edi,%edi
    incl    %edi
    movq    %rsp,%rsi
    xorl    %edx,%edx
    movb    $5,%dl
    syscall
    xorl    %edi,%edi
    xorl    %eax,%eax
    movb    $0x3c,%al
    syscall
