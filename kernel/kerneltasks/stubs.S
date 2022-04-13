.section .text

#include <cpu.h>
#include <x86-64/idt.h>

.global __kernel_task_end
__kernel_task_end:
    mov CPU_TSS_RSP0(%rdi), %rsp
    jmp kernel_task_post_end

.global __kernel_task_yield
__kernel_task_yield:

    /* do the stack pointer first, as we must preserve it before using it */
    mov %rsp, -16(%rsp)
	sub $INT_FRAME_SIZE, %rsp
	/* Do RIP later */
	mov %ss, IF_SS(%rsp)
	/* RSP already done, skip it */
	/* Do RFLAGS later */
	mov %cs, IF_CS(%rsp)
	movq $0, IF_ERR(%rsp)
	movq $0, IF_INO(%rsp)
    mov %rax, IF_RAX(%rsp)
	mov %rcx, IF_RCX(%rsp)
	mov %rdx, IF_RDX(%rsp)
	mov %rbx, IF_RBX(%rsp)
	mov %rbp, IF_RBP(%rsp)
	mov %rsi, IF_RSI(%rsp)
	mov %rdi, IF_RDI(%rsp)
	mov %r8, IF_R8(%rsp)
	mov %r9, IF_R9(%rsp)
	mov %r10, IF_R10(%rsp)
	mov %r11, IF_R11(%rsp)
	mov %r12, IF_R12(%rsp)
	mov %r13, IF_R13(%rsp)
	mov %r14, IF_R14(%rsp)
	mov %r15, IF_R15(%rsp)

	/* Recover the segments. */
	xor %rax, %rax
	mov %ds, %eax
	mov %rax, IF_DS(%rsp)

	/* Do Rflags */
	pushfq
	pop %rax
	mov %rax, IF_RFLAGS(%rsp)

	/* Push the return address of the calling kernel task */
	mov INT_FRAME_SIZE(%rsp), %rax
	mov %rax, IF_RIP(%rsp)

    mov %rdi, %rax
    mov %rsp, %rdi

	/* Switch to the kernel stack */
    mov CPU_TSS_RSP0(%rax), %rsp
    jmp kernel_task_post_yield

.global __kernel_task_start
__kernel_task_start:
	/* Recover the register state. */
	mov %rdi, %rsp
    mov %rdi, %r8
	pop %rax
	mov %rax, %ds

	pop %r15
	pop %r14
	pop %r13
	pop %r12
    add $32, %rsp /* r8 through r11 do not need to be preserved across */
    /* function calls, making them nice scratch registers for us */

	pop %rdi
	pop %rsi
	pop %rbp
	pop %rbx
	pop %rdx
	pop %rcx
	pop %rax

    /* Get the IP to jump to and restore the stack */
    mov IF_RIP(%r8), %r9
    mov IF_RSP(%r8), %rsp

    jmp *%r9
