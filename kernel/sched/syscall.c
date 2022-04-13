#include <error.h>
#include <string.h>
#include <assert.h>
#include <cpu.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>

#include <kernel/acpi.h>
#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>
#include <kernel/debug.h>

extern struct list global_runq;

#ifndef USE_BIG_KERNEL_LOCK
extern struct spinlock global_runq_lock;
#endif

extern void syscall64(void);

void syscall_init(void)
{
#ifdef LAB3_SYSCALL
	// Set the segments to use for the syscall instruction
	write_msr(MSR_STAR, (GDT_UCODE << 16) | GDT_KCODE);

	// Set the entrypoint that the syscall instruction will lead to
	write_msr(MSR_LSTAR, (uintptr_t) syscall64);

	// Set the flags to clear for syscall
	write_msr(MSR_SFMASK, FLAGS_TF | FLAGS_IF);

	// Store the "this_cpu" struct pointer so that we can retrieve it
	// in the syscall64 function later
	write_msr(MSR_KERNEL_GS_BASE, (uintptr_t) this_cpu);

	// Enable the syscall instruction
	write_msr(MSR_EFER, read_msr(MSR_EFER) | MSR_EFER_SCE);
#endif
}

void syscall_init_mp(void)
{
	syscall_init();
}

/*
 * Print a string to the system console.
 * The string is exactly 'len' characters long.
 * Destroys the environment on memory errors.
 */
static void sys_cputs(const char *s, size_t len)
{
	/* Check that the user has permission to read memory [s, s+len).
	 * Destroy the environment if not. */
	assert_user_mem(cur_task, (void*) s, len, 0);

	/* Print the string supplied by the user. */
	cprintf("%.*s", len, s);
}

/*
 * Read a character from the system console without blocking.
 * Returns the character, or 0 if there is no input waiting.
 */
static int sys_cgetc(void)
{
	return cons_getc();
}

/* Returns the PID of the current task. */
static pid_t sys_getpid(void)
{
	return cur_task->task_pid;
}

static int sys_kill(pid_t pid)
{
	struct task *task;

	task = pid2task(pid, 1);

	if (!task) {
		return -1;
	}

	#ifndef USE_BIG_KERNEL_LOCK
		if(task != cur_task) {
			// cur_task is already locked
			spin_lock(&task->task_lock);
		}
	#endif

	if(task->task_status == TASK_DYING || task->killed) {
		return -1;
	}

	task->killed = 1;
	task->killed_by = cur_task->task_pid;

	if(cur_task == task) {
		cprintf("[PID %5u] Exiting gracefully\n", task->task_pid);

		task_destroy(task);
	} else {
		cprintf("[PID %5u] Reaping task with PID %u\n", cur_task->task_pid, pid);

		#ifndef USE_BIG_KERNEL_LOCK
			spin_unlock(&task->task_lock);
		#endif

		// Don't actually kill the task here, as another CPU might be working on it
		// at the moment. Instead, simply mark it as "dying" and let the interrupt
		// handler of the CPU currently working on the task do the rest
	}

	return 0;
}

#ifdef USE_BIG_KERNEL_LOCK
	static void sys_yield(void) {
		sched_update_budget(cur_task);

		uint64_t new_budget = cur_task->task_time_use;

		struct list* node;

		list_foreach(&global_runq, node) {
			struct task* task_node = container_of(node, struct task, task_node);

			if(task_node != cur_task && task_node->task_time_use > new_budget) {
				new_budget = task_node->task_time_use + 1;
			}
		}
		cur_task->task_time_use = new_budget;
		cur_task->task_status = TASK_RUNNABLE;
		sched_yield();

		panic("Should have yielded");
	}
#else // !USE_BIG_KERNEL_LOCK
	static void sys_yield(void) {
		sched_update_budget(cur_task);

		uint64_t new_budget = cur_task->task_time_use;

		struct list* node;

		// Find the lowest budget of
		list_foreach(&this_cpu->runq, node) {
			struct task* task_node = container_of(node, struct task, task_node);

			if(task_node != cur_task && task_node->task_time_use > new_budget) {
				new_budget = task_node->task_time_use + 1;
			}
		}

		list_foreach(&this_cpu->nextq, node) {
			struct task* task_node = container_of(node, struct task, task_node);

			if(task_node != cur_task && task_node->task_time_use > new_budget) {
				new_budget = task_node->task_time_use + 1;
			}
		}

		cur_task->task_time_use = new_budget;

		// Neither queue contains runnable tasks, just add the current task back to the queue and
		// yield
		if(!contains_runnable_tasks(&this_cpu->runq) && !contains_runnable_tasks(&this_cpu->nextq)) {

			cur_task->task_status = TASK_RUNNABLE;
			spin_unlock(&cur_task->task_lock);

			sched_start();

			panic("Should have started");
		}

		// If the nextq contains a task with higher prio than the runq, do that one
		// first
		struct task* nextq_highest_prio = get_highest_prio_task(&this_cpu->nextq);
		if(nextq_highest_prio != NULL) {
			// If we can migrate a higher prio task from the nextq, do that
			list_del(&nextq_highest_prio->task_node);
			list_add(&this_cpu->runq, &nextq_highest_prio->task_node);
			this_cpu->runq_len++;
		}

		cur_task->task_status = TASK_RUNNABLE;
		spin_unlock(&cur_task->task_lock);

		sched_start();
		panic("Should have started");
	}
#endif // USE_BIG_KERNEL_LOCK

static int sys_getcpuid(void) {
	return (int) this_cpu->cpu_id;
}

void ktask_sys_yield(void) {
	sys_yield();
}

/* Dispatches to the correct kernel function, passing the arguments. */
int64_t syscall(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
        uint64_t a4, uint64_t a5, uint64_t a6)
{
	DEBUG_SYSCALL("Handling syscall %lu in task %lu on CPU %u\n", syscallno, cur_task->task_pid, this_cpu->cpu_id);
	/*
	 * Call the function corresponding to the 'syscallno' parameter.
	 * Return any appropriate return value.
	 */
	switch (syscallno) {
		case SYS_cputs:
			sys_cputs((const char*) a1, a2);
			return 0;
			break;
		case SYS_cgetc:
			return sys_cgetc();
			break;
		case SYS_getpid:
			return sys_getpid();
			break;
		case SYS_kill:
			return sys_kill(a1);
			break;
		case SYS_mquery:
			return sys_mquery((struct vma_info*) a1, (void*) a2);
			break;
		case SYS_mmap:
			return (int64_t) sys_mmap((void*) a1, a2, a3, a4, a5, a6);
			break;
		case SYS_munmap:
			sys_munmap((void*) a1, a2);
			return 0;
			break;
		case SYS_mprotect:
			return (int64_t) sys_mprotect((void*) a1, a2, a3);
			break;
		case SYS_madvise:
			return sys_madvise((void*) a1, a2, a3);
			break;
		case SYS_yield:
			sys_yield();
			panic("Should have yielded");
			return 0;
			break;
		case SYS_wait:
			return sys_wait((int*)a1);
			break;
		case SYS_waitpid:
			return sys_waitpid(a1, (int*)a2, a3);
			break;
		case SYS_fork:
			return sys_fork();
			break;
		case SYS_getcpuid:
			return sys_getcpuid();
			break;
		default:
			return -ENOSYS;
	}
}

void syscall_handler(uint64_t syscallno, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, uint64_t a6)
{
	struct int_frame *frame;

	/* Syscall from user mode. */
	assert(cur_task);

	DEBUG_SYSCALL("Fast syscall handler called by task %lu on CPU %u\n", cur_task->task_pid, this_cpu->cpu_id);

	/* Avoid using the frame on the stack. */
	frame = &cur_task->task_frame;

	// Pop the task from the run queue
	list_del(&cur_task->task_node);

	// Make sure to return using syscall64
	frame->int_no = 0x80;

	/* Issue the syscall. */
	frame->rax = syscall(syscallno, a1, a2, a3, a4, a5, a6);

	/* Return to the current task, which should be running. */
	task_run(cur_task);
}
