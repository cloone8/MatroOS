#pragma once

#include <types.h>
#include <list.h>
#include <rbtree.h>
#include <spinlock.h>

#include <x86-64/idt.h>
#include <x86-64/memory.h>

typedef int32_t pid_t;

/* Values of task_status in struct task. */
enum {
	TASK_DYING = 0,
	TASK_IN_INTERRUPT = 1,
	TASK_RUNNABLE = 2,
	TASK_RUNNING = 3,
	TASK_NOT_RUNNABLE = 4,
	TASK_SWAPPING = 5
};

/* The method of interrupt used to switch to the kernel. */
enum {
	TASK_INT = 0,
	TASK_SYSCALL,
};

/* Special task types. */
enum task_type {
	TASK_TYPE_USER = 0,
	TASK_TYPE_KERNEL = 1,
};

struct kernel_task_info {
	void* init_stack_top;
};

struct task {
	/* The saved registers. */
	struct int_frame task_frame;

	/* The task this task is waiting on. */
	struct task *task_wait;

	/* The process ID of this task and its parent. */
	pid_t task_pid;
	pid_t task_ppid;

	/* The task type. */
	enum task_type task_type;

	/* The task status. */
	unsigned task_status;

	/* The number of times the task has been run. */
	unsigned task_runs;

	/* The CPU that the task is running on. */
	int task_cpunum;

	// Whether this task is marked for destruction
	int killed;
	pid_t killed_by;
	volatile int user_mem_freed;

	/* The virtual address space. */
	struct page_table *task_pml4;

	/* The VMAs */
	struct rb_tree task_rb;
	struct list task_mmap;

	/* The children */
	struct list task_children;
	struct list task_child;

	/* The zombies */
	struct list task_zombies;

	/* The anchor node (for zombies or the run queue) */
	struct list task_node;

	/* Counter to keep track of round robin prio */
	uint64_t task_time_use;

	/* Timer to keep track of runtimes */
	uint64_t task_time;
#ifndef USE_BIG_KERNEL_LOCK
	/* Per-task lock */
	struct spinlock task_lock;
#endif

	struct kernel_task_info* task_kern_info;
};
