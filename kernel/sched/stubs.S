.section .text

#include <x86-64/gdt.h>
#include <x86-64/idt.h>
#include <x86-64/memory.h>

#include <cpu.h>


#define CPU_TASK_INT_FRAME_RAX 0x80
; #define INT_FRAME_CS 0x98
#define TASK_TASK_STATUS 0xcc
#define TASK_STATUS_TASK_RUNNING 0x3

.macro ISR_NOERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $0
	pushq $\int_no
	jmp isr_common_stub
.endm

.macro ISR_ERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $\int_no
	jmp isr_common_stub
.endm

/* These macros define the isr functions */
	ISR_NOERRCODE 0
/* RESERVED fault/trap skipped (for Intel use only) */
	ISR_NOERRCODE 2
	ISR_NOERRCODE 3
	ISR_NOERRCODE 4
	ISR_NOERRCODE 5
	ISR_NOERRCODE 6
	ISR_NOERRCODE 7
	ISR_ERRCODE 8
	ISR_NOERRCODE 9
	ISR_ERRCODE 10
	ISR_ERRCODE 11
	ISR_ERRCODE 12
	ISR_ERRCODE 13
	ISR_ERRCODE 14
/* 15 skipped, intel reserved */
	ISR_NOERRCODE 16
	ISR_ERRCODE 17
	ISR_NOERRCODE 18
	ISR_NOERRCODE 19
/* 20-31 reserved by Intel */
/* Hardware interrupts */
	ISR_NOERRCODE 32

/* Syscalls */
	ISR_NOERRCODE INT_SYSCALL

/* LAB 3: your code here. */

isr_common_stub:
	push %rax
	push %rcx
	push %rdx
	push %rbx
	push %rbp
	push %rsi
	push %rdi

	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15

	/* Recover the segments. */
	xor %rax, %rax
	mov %ds, %eax
	push %rax

	/* Jump to the generic interrupt handler. */
	movq %rsp, %rdi
	jmp int_handler

.global syscall64
syscall64:
	swapgs

	/* Store the user stack pointer into the per-cpu struct. */
	mov %rsp, %gs:CPU_TSS_RSP3

	/* Store the register state into the per-cpu struct. */
	mov %gs:CPU_TASK, %rsp
	add $CPU_TASK_INT_FRAME_RAX, %rsp

	push %rax
	push %rcx
	push %rdx
	push %rbx
	push %rbp
	push %rsi
	push %rdi
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15

	/* Load the kernel stack pointer from the per-cpu struct. */
	mov %gs:CPU_TSS_RSP0, %rsp

	/* Jump to the system call handler. */
	movq %r10, %rcx
	pushq %rbp
	pushq $0
	jmp syscall_handler

.global iret64
iret64:
	/* Restore the register state. */
	mov %rdi, %rsp
	pop %rax
	mov %rax, %ds

	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8

	pop %rdi
	pop %rsi
	pop %rbp
	pop %rbx
	pop %rdx
	pop %rcx
	pop %rax

	/* Return from the interrupt. */
	addq $16, %rsp
	iretq

.global sysret64
sysret64:
	/* Recover the register state. */
	mov %rdi, %rsp
	pop %rax
	mov %rax, %ds

	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8

	pop %rdi
	pop %rsi
	pop %rbp
	pop %rbx
	pop %rdx
	pop %rcx
	pop %rax

	/* Restore the original GS value and the user stack pointer */
	mov %gs:CPU_TSS_RSP3, %rsp
	swapgs

	/* Return from the system call. */
	sysretq
