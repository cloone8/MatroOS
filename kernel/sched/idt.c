#include <assert.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>
#include <x86-64/idt.h>

#include <kernel/acpi.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>
#include <kernel/debug.h>

#define IDT_ENTRY_SETTER(idx, flags) (set_idt_entry(entries + (idx), isr##idx, (IDT_PRESENT | (flags)), GDT_KCODE))

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif

#ifndef USE_BIG_KERNEL_LOCK
extern struct spinlock global_runq_lock;
#endif

static const char *int_names[256] = {
	[INT_DIVIDE] = "Divide-by-Zero Error Exception (#DE)",
	[INT_DEBUG] = "Debug (#DB)",
	[INT_NMI] = "Non-Maskable Interrupt",
	[INT_BREAK] = "Breakpoint (#BP)",
	[INT_OVERFLOW] = "Overflow (#OF)",
	[INT_BOUND] = "Bound Range (#BR)",
	[INT_INVALID_OP] = "Invalid Opcode (#UD)",
	[INT_DEVICE] = "Device Not Available (#NM)",
	[INT_DOUBLE_FAULT] = "Double Fault (#DF)",
	[INT_TSS] = "Invalid TSS (#TS)",
	[INT_NO_SEG_PRESENT] = "Segment Not Present (#NP)",
	[INT_SS] = "Stack (#SS)",
	[INT_GPF] = "General Protection (#GP)",
	[INT_PAGE_FAULT] = "Page Fault (#PF)",
	[INT_FPU] = "x86 FPU Floating-Point (#MF)",
	[INT_ALIGNMENT] = "Alignment Check (#AC)",
	[INT_MCE] = "Machine Check (#MC)",
	[INT_SIMD] = "SIMD Floating-Point (#XF)",
	[INT_SECURITY] = "Security (#SX)",
	[INT_SYSCALL] = "System call",
	[IRQ_TIMER] = "Timer"
};

static struct idt_entry entries[256];
static struct idtr idtr = {
	.limit = sizeof(entries) - 1,
	.entries = entries,
};

static const char *get_int_name(unsigned int_no)
{
	if (!int_names[int_no])
		return "Unknown Interrupt";

	return int_names[int_no];
}

void print_int_frame(struct int_frame *frame)
{
	cprintf("INT frame at %p\n", frame);

	/* Print the interrupt number and the name. */
	cprintf(" INT %u: %s\n",
		frame->int_no,
		get_int_name(frame->int_no));

	/* Print the error code. */
	switch (frame->int_no) {
	case INT_PAGE_FAULT:
		cprintf(" CR2 %p\n", read_cr2());
		cprintf(" ERR 0x%016llx (%s%s, %s, %s)\n",
			frame->err_code,
			frame->err_code & PF_IFETCH ? "ifetch, " : "",
			frame->err_code & PF_USER ? "user" : "kernel",
			frame->err_code & PF_WRITE ? "write" : "read",
			frame->err_code & PF_PRESENT ? "protection" : "not present");
		break;
	default:
		cprintf(" ERR 0x%016llx\n", frame->err_code);
	}

	/* Print the general-purpose registers. */
	cprintf(" RAX 0x%016llx"
		" RCX 0x%016llx"
		" RDX 0x%016llx"
		" RBX 0x%016llx\n"
		" RSP 0x%016llx"
		" RBP 0x%016llx"
		" RSI 0x%016llx"
		" RDI 0x%016llx\n"
		" R8  0x%016llx"
		" R9  0x%016llx"
		" R10 0x%016llx"
		" R11 0x%016llx\n"
		" R12 0x%016llx"
		" R13 0x%016llx"
		" R14 0x%016llx"
		" R15 0x%016llx\n",
		frame->rax, frame->rcx, frame->rdx, frame->rbx,
		frame->rsp, frame->rbp, frame->rsi, frame->rdi,
		frame->r8,  frame->r9,  frame->r10, frame->r11,
		frame->r12, frame->r13, frame->r14, frame->r15);

	/* Print the IP, segment selectors and the RFLAGS register. */
	cprintf(" RIP 0x%016llx"
		" RFL 0x%016llx\n"
		" CS  0x%04x"
		"            "
		" DS  0x%04x"
		"            "
		" SS  0x%04x\n",
		frame->rip, frame->rflags,
		frame->cs, frame->ds, frame->ss);
}


/* Set up the interrupt handlers. */
void idt_init(void)
{
	IDT_ENTRY_SETTER(0, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(2, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(3, IDT_PRIVL(3) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(4, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(5, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(6, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(7, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(8, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(9, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(10, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(11, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(12, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(13, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(14, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(16, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(17, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(18, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(19, IDT_PRIVL(0) | IDT_INT_GATE32);
	IDT_ENTRY_SETTER(32, IDT_PRIVL(0) | IDT_INT_GATE32);

	// Syscalls
	set_idt_entry(entries + INT_SYSCALL, isr128, IDT_PRESENT | IDT_PRIVL(3) | IDT_INT_GATE32, GDT_KCODE);

	load_idt(&idtr);
}

void idt_init_mp(void)
{
	load_idt(&idtr);
}

void int_dispatch(struct int_frame *frame)
{
	/* Handle processor exceptions:
	 *  - Fall through to the kernel monitor on a breakpoint.
	 *  - Dispatch page faults to page_fault_handler().
	 *  - Dispatch system calls to syscall().
	 */
	switch (frame->int_no) {
		case INT_BREAK:
			DEBUG_INT_HANDLER("INT %lu in CPU %u dispatched to INT_BREAK handler\n", frame->int_no, this_cpu->cpu_id);
			monitor(frame);
			return;
			break;
		case INT_PAGE_FAULT:
			DEBUG_INT_HANDLER("INT %lu in CPU %u dispatched to INT_PAGE_FAULT handler\n", frame->int_no, this_cpu->cpu_id);
			page_fault_handler(frame);
			return;
			break;
		case INT_SYSCALL:
			DEBUG_INT_HANDLER("INT %lu in CPU %u dispatched to INT_SYSCALL handler\n", frame->int_no, this_cpu->cpu_id);
			frame->rax = syscall(frame->rdi, frame->rsi, frame->rdx, frame->rcx, frame->r8, frame->r9, 0);
			return;
			break;
		case IRQ_TIMER:
			DEBUG_INT_HANDLER("INT %lu in CPU %u dispatched to IRQ_TIMER handler\n", frame->int_no, this_cpu->cpu_id);
			apic_timer_handler();
			return;
			break;
		default:
			DEBUG_INT_HANDLER("INT %lu in CPU %u not dispatched\n", frame->int_no, this_cpu->cpu_id);
			break;
	}

	/* Unexpected trap: The user process or the kernel has a bug. */
	print_int_frame(frame);

	if (frame->cs == GDT_KCODE) {
		panic("Unhandled interrupt in kernel");
	} else {
		task_kill(cur_task);
		panic("Should be running a new task");
	}
}

void int_handler(struct int_frame *frame)
{
	/* The task may have set DF and some versions of GCC rely on DF being
	 * clear. */
	asm volatile("cld" ::: "cc");

	// cprintf("frame: %p\n", frame);
	// cprintf("cs: %p\n", (void*)&frame->cs - (void*) frame);
	// cprintf("ds: %p\n", (void*)&frame->ds - (void*) frame);
	// cprintf("ss: %p\n", (void*)&frame->ss - (void*) frame);
	// cprintf("rax: %p\n", (void*)&frame->rax - (void*) frame);

	/* Check if interrupts are disabled.
	 * If this assertion fails, DO NOT be tempted to fix it by inserting a
	 * "cli" in the interrupt path.
	 */
	assert(!(read_rflags() & FLAGS_IF));

	#ifdef USE_BIG_KERNEL_LOCK
		spin_lock(&kernel_lock);
	#endif

	if ((frame->cs & 3) == 3) {
		// Interrupt from user mode
		DEBUG_INT_HANDLER("Incoming INT %lu from userspace for CPU %u running task %lu\n", frame->int_no, this_cpu->cpu_id, cur_task->task_pid);

		assert(cur_task);

		#ifndef USE_BIG_KERNEL_LOCK
			spin_lock(&cur_task->task_lock);
		#endif

		cur_task->task_status = TASK_IN_INTERRUPT;

		/* Copy interrupt frame (which is currently on the stack) into
		 * 'cur_task->task_frame', so that running the task will restart at
		 * the point of interrupt. */
		cur_task->task_frame = *frame;

		/* Avoid using the frame on the stack. */
		frame = &cur_task->task_frame;

		// If this task was marked to be killed by another CPU, do that here. Other faults
		// do not matter at that point. This also starts a new task
		if(cur_task->killed == 1) {
			DEBUG_INT_HANDLER("Task %lu on CPU %u was marked to be killed. Destroying the task and starting a new one.\n", cur_task->task_pid, this_cpu->cpu_id);
			task_destroy(cur_task);
			panic("Should have yielded");
		}

		/* Dispatch based on the type of interrupt that occurred. */
		int_dispatch(frame);

		/* Return to the current task, which should be running. */
		DEBUG_INT_HANDLER("INT %lu in CPU %u back from dispatch, running...\n", frame->int_no, this_cpu->cpu_id);

		assert(cur_task->task_status == TASK_IN_INTERRUPT);
		list_del(&cur_task->task_node);
		cur_task->task_status = TASK_RUNNABLE;

		task_run(cur_task);
	} else {
		// Interrupt from kernel
		/* Dispatch based on the type of interrupt that occurred. */
		DEBUG_INT_HANDLER("Incoming INT %lu from kernelspace for CPU %u running task %lu\n", frame->int_no, this_cpu->cpu_id, cur_task ? cur_task->task_pid : 0);

		if(cur_task && cur_task->task_status == TASK_RUNNING) {
			#ifndef USE_BIG_KERNEL_LOCK
				spin_lock(&cur_task->task_lock);
			#endif

			cur_task->task_status = TASK_IN_INTERRUPT;
			cur_task->task_frame = *frame;

			/* Avoid using the frame on the stack. */
			frame = &cur_task->task_frame;

			// If this task was marked to be killed by another CPU, do that here. Other faults
			// do not matter at that point. This also starts a new task
			if(cur_task->killed == 1) {
				DEBUG_INT_HANDLER("Task %lu on CPU %u was marked to be killed. Destroying the task and starting a new one.\n", cur_task->task_pid, this_cpu->cpu_id);
				task_destroy(cur_task);
				panic("Should have yielded");
			}
		}

		int_dispatch(frame);

		// The only possible way out of int_dispatch would be a call to sys_kill
		// for the kernel task, which should only be possible on itself. This
		// way, the scheduler will start a new task, making the return out of
		// int_dispatch impossible
		panic("Should not get here");
	}
}

void page_fault_handler(struct int_frame *frame)
{
	void *fault_va;
	unsigned perm = 0;
	int ret;

	// Get the flags from the error code
	int retrieved_flags = 0;

	retrieved_flags |= frame->err_code & PF_PRESENT;
	retrieved_flags |= frame->err_code & PF_WRITE;
	retrieved_flags |= frame->err_code & PF_USER;
	retrieved_flags |= frame->err_code & PF_RESERVED;
	retrieved_flags |= frame->err_code & PF_IFETCH;

	/* Read the CR2 register to find the faulting address. */
	fault_va = (void *)read_cr2();

	/* Handle kernel-mode page faults. */
	if(!(frame->err_code & PF_USER)) {
		panic(
			"Kernel page fault!\n"
			"IP: %p\n"
			"VA: %p\n"
			"Error flags:\n"
			"    Present: %d\n"
			"    Write: %d\n"
			"    User: %d\n"
			"    Reserved: %d\n"
			"    IFetch: %d\n"
			,frame->rip, fault_va,
			(retrieved_flags & PF_PRESENT) != 0,
			(retrieved_flags & PF_WRITE) != 0,
			(retrieved_flags & PF_USER) != 0,
			(retrieved_flags & PF_RESERVED) != 0,
			(retrieved_flags & PF_IFETCH) != 0
		);
	}

	/* We have already handled kernel-mode exceptions, so if we get here, the
	 * page fault has happened in user mode.
	 */

	if(task_page_fault_handler(cur_task, fault_va, retrieved_flags) >= 0) {
		return;
	} else {
		/* Destroy the task that caused the fault. */
		cprintf("[PID %5u] user fault va %p ip %p\n",
			cur_task->task_pid, fault_va, frame->rip);
		print_int_frame(frame);
		task_kill(cur_task);
		return;
	}
}

void apic_timer_handler() {
	// Set the task to runnable, for rescheduling
	cur_task->task_status = TASK_RUNNABLE;

	sched_update_budget(cur_task);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&cur_task->task_lock);
	#endif

	lapic_eoi();

	#ifdef USE_BIG_KERNEL_LOCK
		sched_yield();
		panic("Should have yielded");
	#else
		sched_start();
		panic("Should have started");
	#endif
}
