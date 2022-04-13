#include <error.h>
#include <string.h>
#include <paging.h>
#include <task.h>
#include <cpu.h>
#include <atomic.h>

#include <kernel/acpi.h>
#include <kernel/monitor.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>
#include <kernel/debug.h>
#include <kernel/kerneltasks.h>
#include <elf.h>

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif

#ifndef USE_BIG_KERNEL_LOCK
extern struct spinlock global_runq_lock;
extern struct spinlock buddy_lock;
#endif

extern struct list buddy_free_list[BUDDY_MAX_ORDER];

struct task **tasks = (struct task **)PIDMAP_BASE;

volatile size_t nuser_tasks = 0;
volatile size_t nkernel_tasks = 0;

extern struct list global_runq;

/*
 * Generate PRN based on the linear congruential generator.
 */
static unsigned int get_random_int(size_t i_count) {
	unsigned int ret = 0;

	unsigned int seed = read_tsc();
	unsigned int mod = 1 << 15; // For efficient computation.
	unsigned int a = 7; // Chosen at random.
	unsigned int c = 85; // Chosen at random.

	for (size_t i = 0; i < i_count; i++) {
		ret = (a * seed + c) % mod;
	}

	return ret;
}

/* Looks up the respective task for a given PID.
 * If check_perm is non-zero, this function checks if the PID maps to the
 * current task or if the current task is the parent of the task that the PID
 * maps to.
 */
struct task *pid2task(pid_t pid, int check_perm)
{
	struct task *task;

	/* PID 0 is the current task. */
	if (pid == 0) {
		return cur_task;
	}

	/* Limit the PID. */
	if (pid >= PID_MAX) {
		return NULL;
	}

	/* Look up the task in the PID map. */
	task = tasks[pid];

	/* No such mapping found. */
	if (!task) {
		return NULL;
	}

	/* If we don't have to do a permission check, we can simply return the
	 * task.
	 */
	if (!check_perm) {
		return task;
	}

	/* Check if the task is the current task or if the current task is the
	 * parent. If not, then the current task has insufficient permissions.
	 */
	if (task != cur_task && task->task_ppid != cur_task->task_pid) {
		return NULL;
	}

	return task;
}

void task_init(void)
{
	const size_t tasks_array_size = PID_MAX * sizeof(struct task*);

	populate_region(kernel_pml4, tasks, tasks_array_size, PAGE_WRITE | PAGE_NO_EXEC, 0);
}

/* Sets up the virtual address space for the task. */
static int task_setup_vas(struct task *task)
{
	if(task->task_type == TASK_TYPE_USER) {
		struct page_info *page;

		/* Allocate a page for the page table. */
		page = page_alloc(ALLOC_ZERO);

		if (!page) {
			return -ENOMEM;
		}

		atomic_inc(&page->pp_ref);

		struct page_table* task_pml4 = page2kva(page);

		for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
			task_pml4->entries[i] = kernel_pml4->entries[i];
		}
		task->task_pml4 = task_pml4;

		return 0;
	} else {
		task->task_pml4 = kernel_pml4;

		return 0;
	}
}

static pid_t find_free_pid(enum task_type type) {
	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	const pid_t min_pid = type == TASK_TYPE_USER ? 1 : PID_MAX / 2;

	for (pid_t pid = min_pid; pid < PID_MAX; ++pid) {
		if (!tasks[pid]) {
			return pid;
		}
	}

	return PID_MAX;
}

/* Allocates and initializes a new task.
 * On success, the new task is returned.
 */
struct task *task_alloc(pid_t ppid)
{
	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	// Set up the most important config
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_USER;

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	pid = find_free_pid(task->task_type);

	if(pid != PID_MAX) {
		tasks[pid] = task;
		task->task_pid = pid;
	} else {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_status = TASK_RUNNABLE;
	task->task_runs = 0;
	task->task_time_use = 0;
	task->task_time = read_tsc();
	task->killed = 0;
	task->killed_by = 0;
	task->user_mem_freed = 0;

	#ifndef USE_BIG_KERNEL_LOCK
		memset(&task->task_lock, 0, sizeof(struct spinlock));

		#ifdef DEBUG_SPINLOCK
			char* task_lock_string = kmalloc(32);

			task->task_lock.name = kmalloc(32);
			assert(task->task_lock.name != NULL);

			snprintf((char*)task->task_lock.name, 31, "task_%u_task_lock", task->task_pid);
		#endif
	#endif

	list_init(&task->task_mmap);
	rb_init(&task->task_rb);

	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_UDATA | 3;
	task->task_frame.ss = GDT_UDATA | 3;
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.cs = GDT_UCODE | 3;
	task->task_frame.rflags |= FLAGS_IF;

	// Set up scheduling list nodes
	list_init(&task->task_children);
	list_init(&task->task_child);
	list_init(&task->task_zombies);
	list_init(&task->task_node);

	// Add the task to the parents' list of children and change the initial
	// "time used" budget to the time used by the parent
	if(ppid != 0) {
		struct task* parent = pid2task(ppid, 0);

		assert(parent != NULL);

		list_add(&parent->task_children, &task->task_child);
		task->task_time_use = parent->task_time_use;
	}

	cprintf("[PID %5u] New task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);

	return task;
}

/* Allocates and initializes a new task.
 * On success, the new task is returned.
 */
struct task *kernel_task_alloc(pid_t ppid)
{
	struct task *task;
	pid_t pid;

	if(ppid != 0) {
		panic("Not supported");
	}

	/* Allocate a new task struct. */
	task = kmalloc(sizeof(struct task));

	if (!task) {
		return NULL;
	}

	task->task_kern_info = kmalloc(sizeof(struct kernel_task_info));

	if(!task->task_kern_info) {
		return NULL;
	}

	// Set the most important config
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_KERNEL;

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	pid = find_free_pid(task->task_type);

	if(pid != PID_MAX) {
		tasks[pid] = task;
		task->task_pid = pid;
	} else {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_status = TASK_RUNNABLE;
	task->task_runs = 0;
	task->task_time_use = 0;
	task->task_time = read_tsc();
	task->killed = 0;
	task->killed_by = 0;
	task->user_mem_freed = 0;

	#ifndef USE_BIG_KERNEL_LOCK
		memset(&task->task_lock, 0, sizeof(struct spinlock));

		#ifdef DEBUG_SPINLOCK
			char* task_lock_string = kmalloc(32);

			task->task_lock.name = kmalloc(32);
			assert(task->task_lock.name != NULL);

			snprintf((char*) task->task_lock.name, 31, "ktask_%u_task_lock", task->task_pid);
		#endif
	#endif

	list_init(&task->task_mmap);
	rb_init(&task->task_rb);

	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_KDATA;
	task->task_frame.cs = GDT_KCODE;
	task->task_frame.ss = GDT_KDATA;
	task->task_frame.rflags |= FLAGS_IF;

	// Set up scheduling list nodes
	list_init(&task->task_children);
	list_init(&task->task_child);
	list_init(&task->task_zombies);
	list_init(&task->task_node);

	// Add the task to the parents' list of children and change the initial
	// "time used" budget to the time used by the parent
	if(ppid != 0) {
		struct task* parent = pid2task(ppid, 0);

		assert(parent != NULL);
		assert(parent->task_type == TASK_TYPE_KERNEL);

		list_add(&parent->task_children, &task->task_child);
		task->task_time_use = parent->task_time_use;
	}

	cprintf("[PID %5u] New kernel task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);

	return task;
}


struct task* kernel_task_create(int (*main_func) (void)) {
    struct task* kernel_task = kernel_task_alloc(0);

	if(!kernel_task) {
		// Retry once
		oom();
		kernel_task = kernel_task_alloc(0);

		if(!kernel_task) {
			return NULL;
		}
	}

	kernel_task->task_frame.rip = (uint64_t)&kernel_task_main;
	kernel_task->task_frame.rdi = (uint64_t)main_func;

	// Allocate a new kernel stack just for this task
	kernel_task->task_kern_info->init_stack_top = kernel_task_alloc_stack(kernel_task->task_pml4);
	kernel_task->task_frame.rsp = (uint64_t) kernel_task->task_kern_info->init_stack_top;

	cprintf("Created ktask rsp %p\n", kernel_task->task_frame.rsp);

	atomic_inc(&nkernel_tasks);

	#ifndef USE_BIG_KERNEL_LOCK
    	spin_lock(&global_runq_lock);
	#endif

    list_add(&global_runq, &kernel_task->task_node);

	#ifndef USE_BIG_KERNEL_LOCK
    	spin_unlock(&global_runq_lock);
	#endif

	return kernel_task;
}


static const char* text_str = ".text";
static const char* rodata_str = ".rodata";
static const char* bss_str = ".bss";
static const char* data_str = ".data";

static char* find_vma_name(int flags, struct elf_proghdr* phdr) {
	assert(phdr != NULL);

	if(flags & VM_EXEC) {
		return (char*) text_str;
	}

	if(!(flags & VM_WRITE)) {
		return (char*) rodata_str;
	}

	if(phdr->p_filesz == 0) {
		return (char*) bss_str;
	}

	if(flags & VM_READ) {
		return (char*) data_str;
	}

	panic("Could not determine VMA string");
}

/* Sets up the initial program binary, stack and processor flags for a user
 * process.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode environment.
 *
 * This function loads all loadable segments from the ELF binary image into the
 * task's user memory, starting at the appropriate virtual addresses indicated
 * in the ELF program header.
 * At the same time it clears to zero any portions of these segments that are
 * marked in the program header as being mapped but not actually present in the
 * ELF file, i.e., the program's .bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk. Take a look at boot/main.c to
 * get some ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 */
static void task_load_elf(struct task *task, uint8_t *binary)
{
	struct elf* elf_hdr = (struct elf*) binary;
	struct elf_proghdr* elf_phdrs = (struct elf_proghdr*) (binary + elf_hdr->e_phoff);

	if(task->task_type == TASK_TYPE_USER && elf_hdr->e_entry >= USER_LIM) {
		panic("User task attempting to set entrypoint in kernel space\n");
	}

	/* Hints:
	 * - Load each program segment into virtual memory at the address
	 *   specified in the ELF section header.
	 * - You should only load segments with type ELF_PROG_LOAD.
	 * - Each segment's virtual address can be found in p_va and its
	 *   size in memory can be found in p_memsz.
	 * - The p_filesz bytes from the ELF binary, starting at binary +
	 *   p_offset, should be copied to virtual address p_va.
	 * - Any remaining memory bytes should be zero.
	 * - Use populate_region() and protect_region().
	 * - Check for malicious input.
	 *
	 * Loading the segments is much simpler if you can move data directly
	 * into the virtual addresses stored in the ELF binary.
	 * So in which address space should we be operating during this
	 * function?
	 *
	 * You must also do something with the entry point of the program, to
	 * make sure that the task starts executing there.
	 */

	for(uint16_t i = 0; i < elf_hdr->e_phnum; i++) {
		struct elf_proghdr* p_hdr = elf_phdrs + i;

		if(p_hdr->p_type != ELF_PROG_LOAD) {
			continue;
		}

		if(p_hdr->p_memsz == 0) {
			continue;
		}

		if(p_hdr->p_memsz < p_hdr->p_filesz) {
			panic("Binary filesize cannot be larger than binary memorysize\n");
		}

		if(task->task_type == TASK_TYPE_USER && (p_hdr->p_va >= USER_LIM || p_hdr->p_va + p_hdr->p_memsz >= USER_LIM)) {
			panic("User task attempting to load into kernel space\n");
		}

		int flags = 0;

		if(p_hdr->p_flags & ELF_PROG_FLAG_READ) {
			flags |= VM_READ;
		}

		if(p_hdr->p_flags & ELF_PROG_FLAG_WRITE) {
			flags |= VM_WRITE;
		}

		if(p_hdr->p_flags & ELF_PROG_FLAG_EXEC) {
			flags |= VM_EXEC;
		}

		char* vma_name = find_vma_name(flags, p_hdr);

		if(p_hdr->p_filesz > 0) {
			struct vma* retval = add_executable_vma(task, vma_name, (void*) p_hdr->p_va, p_hdr->p_memsz, flags, binary + p_hdr->p_offset, p_hdr->p_filesz);
			assert(retval != NULL);
		} else {
			struct vma* retval = add_anonymous_vma(task, vma_name, (void*) p_hdr->p_va, p_hdr->p_memsz, flags);
			assert(retval != NULL);
		}
	}

	// Set the entrypoint
	task->task_frame.rip = elf_hdr->e_entry;

	#ifdef BONUS_LAB3
		size_t SHT_REL = 9;
        struct elf_secthdr *sect_header = (struct elf_secthdr*) (binary + elf_hdr->e_shoff);
        for (size_t i = 0; i < elf_hdr->e_shnum; i++) {
			struct elf_secthdr *section = &sect_header[i];
			if (section->sh_type == SHT_REL) {
				// TODO
			}
		}
	#endif

	/* Now map one page for the program's initial stack at virtual address
	 * USTACK_TOP - PAGE_SIZE.
	 */
	add_anonymous_vma(task, "stack", (void*)(USTACK_TOP - PAGE_SIZE), PAGE_SIZE, VM_READ | VM_WRITE);
}

/* Allocates a new task with task_alloc(), loads the named ELF binary using
 * task_load_elf() and sets its task type.
 * If the task is a user task, increment the number of user tasks.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode task.
 * The new task's parent PID is set to 0.
 */
void task_create(uint8_t *binary, enum task_type type)
{
    struct task *new_task = task_alloc(0);

	if(!new_task) {
		// Retry once
		oom();
		new_task = task_alloc(0);

		assert_oom(new_task);
	}

    new_task->task_type = type;
    task_load_elf(new_task, binary);

    if (type == TASK_TYPE_USER) {
		atomic_inc(&nuser_tasks);
	}

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&global_runq_lock);
	#endif

	list_add(&global_runq, &new_task->task_node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&global_runq_lock);
	#endif
}

void task_final_free(struct task* task) {
	assert(task != NULL);
	assert(task->task_status == TASK_DYING);

	DEBUG_TASK_FREE("CPU %u doing final free for task %lu\n", this_cpu->cpu_id, task->task_pid);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&task->task_lock);

		#ifdef DEBUG_SPINLOCK
			kfree((char*) task->task_lock.name);
		#endif
	#endif

	/* Unmap the task from the PID map. */
	tasks[task->task_pid] = NULL;

	/* Free the task. */
	kfree(task);
}

#ifdef USE_BIG_KERNEL_LOCK
	static void task_detach_children(struct task* task) {
		DEBUG_TASK_FREE("CPU %u detaching children for task %lu\n", this_cpu->cpu_id, task->task_pid);
		struct list* node;
		struct list* next;
		struct task* parent = NULL;

		if(task->task_ppid != 0) {
			parent = pid2task(task->task_ppid, 0);
			assert(parent != NULL);

			DEBUG_TASK_FREE("Task %lu has parent %lu\n", task->task_pid, parent->task_pid);
		}

		list_foreach_safe(&task->task_children, node, next) {
			struct task* child_task = container_of(node, struct task, task_child);

			DEBUG_TASK_FREE("CPU %u detaching child %lu\n", this_cpu->cpu_id, child_task->task_pid);

			child_task->task_ppid = task->task_ppid;
			list_del(&child_task->task_child);

			if(parent != NULL) {
				list_add(&parent->task_children, &child_task->task_child);
			}
		}

		list_foreach_safe(&task->task_zombies, node, next) {
			struct task* zombie_task = container_of(node, struct task, task_node);

			DEBUG_TASK_FREE("CPU %u killing zombie %lu\n", this_cpu->cpu_id, zombie_task->task_pid);

			list_del(&zombie_task->task_node);

			task_final_free(zombie_task);
		}

		DEBUG_TASK_FREE("Done detaching children for task %lu\n", task->task_pid);
	}
#else
	static void task_detach_children(struct task* task, struct task* parent) {
		DEBUG_TASK_FREE("CPU %u detaching children for task %lu\n", this_cpu->cpu_id, task->task_pid);
		struct list* node;
		struct list* next;

		list_foreach_safe(&task->task_children, node, next) {
			struct task* child_task = container_of(node, struct task, task_child);

			DEBUG_TASK_FREE("CPU %u detaching child %lu\n", this_cpu->cpu_id, child_task->task_pid);

			spin_lock(&child_task->task_lock);

			child_task->task_ppid = task->task_ppid;
			list_del(&child_task->task_child);

			if(parent != NULL) {
				list_add(&parent->task_children, &child_task->task_child);
			}

			spin_unlock(&child_task->task_lock);
		}

		list_foreach_safe(&task->task_zombies, node, next) {
			struct task* zombie_task = container_of(node, struct task, task_node);

			DEBUG_TASK_FREE("CPU %u killing zombie %lu\n", this_cpu->cpu_id, zombie_task->task_pid);

			spin_lock(&zombie_task->task_lock);

			list_del(&zombie_task->task_node);

			task_final_free(zombie_task);
		}

		DEBUG_TASK_FREE("Done detaching children for task %lu\n", task->task_pid);
	}
#endif

/* Free the task and all of the memory that is used by it.
 */
void task_free(struct task *task)
{
#ifdef USE_BIG_KERNEL_LOCK
	assert(task != NULL);
	assert(task->task_status == TASK_DYING);

	DEBUG_TASK_FREE("CPU %u freeing task %lu\n", this_cpu->cpu_id, task->task_pid);

	struct task* parent = NULL;
	if(task->task_ppid != 0) {
		parent = pid2task(task->task_ppid, 0);
		assert(parent != NULL);

		DEBUG_TASK_FREE("Task %lu has parent %lu\n", task->task_pid, parent->task_pid);
	}

	/* If we are freeing the current task, switch to the kernel_pml4
	 * before freeing the page tables, just in case the page gets re-used.
	 */
	if (task == cur_task) {
		load_pml4((struct page_table *)PADDR(kernel_pml4));
	}

	/* Note the task's demise. */
	cprintf("[PID %5u] Freed task with PID %u\n", task->killed_by,
		task->task_pid);

	/* Free the VMAs */
	free_vmas(task);

	/* Unmap the user pages. */
	unmap_user_pages(task->task_pml4);

	task->user_mem_freed = 1;

	if(task->task_type == TASK_TYPE_KERNEL) {
		kernel_task_remove_stack(task);
	}

	task_detach_children(task);

	if(task->task_type == TASK_TYPE_USER) {
		atomic_dec(&nuser_tasks);
	}

	if(parent != NULL) {
		// Remove from any parent children lists
		list_del(&task->task_child);
		list_add(&parent->task_zombies, &task->task_node);

		// Notify waiting parent
		if(parent->task_status == TASK_NOT_RUNNABLE) {
			if(parent->task_wait == NULL || parent->task_wait->task_pid == task->task_pid) {
				parent->task_wait = NULL;

				parent->task_frame.rax = task->task_pid;

				parent->task_status = TASK_RUNNABLE;
			}
		}
	} else {
		DEBUG_TASK_FREE("Task %lu has NULL parent, doing final free\n", task->task_pid);
		task_final_free(task);
	}
#else
	assert(task != NULL);
	assert(task->task_status == TASK_DYING);

	DEBUG_TASK_FREE("CPU %u freeing task %lu\n", this_cpu->cpu_id, task->task_pid);

	struct task *parent = NULL;
	volatile pid_t* parent_id = &task->task_ppid;

	int task_locked = 1;
	pid_t current_parent = *parent_id;
	while(current_parent != 0) {
		parent = pid2task(current_parent, 0);
		assert(parent != NULL);

		DEBUG_TASK_FREE("Task %lu has parent %lu\n", task->task_pid, parent->task_pid);
		DEBUG_TASK_FREE("CPU %u trying to lock both task %lu and parent %lu\n", this_cpu->cpu_id, task->task_pid, parent->task_pid);

		if(task_locked) {
			spin_unlock(&task->task_lock);
		}

		task_locked = spin_trylock(&task->task_lock);
		const int parent_locked = spin_trylock(&parent->task_lock);

		// We need to get a lock on both the child and parent processes, to
		// make sure we can transfer children properly
		if(!(task_locked && parent_locked)) {
			if(task_locked)
				spin_unlock(&task->task_lock);

			if(parent_locked)
				spin_unlock(&parent->task_lock);

			task_locked = 0;
		} else {
			// Now both the task and the parent should be locked
			DEBUG_TASK_FREE("CPU %u got both locks\n", this_cpu->cpu_id);
			break;
		}

		 // Maybe the parent has changed in the meantime
		current_parent = *parent_id;
		parent = NULL;
	}

	if(!task_locked) {
		spin_lock(&task->task_lock);
	}

	/* If we are freeing the current task, switch to the kernel_pml4
	 * before freeing the page tables, just in case the page gets re-used.
	 */
	if (task == cur_task && task->task_type != TASK_TYPE_KERNEL) {
		load_pml4((struct page_table *)PADDR(kernel_pml4));
	}



	/* Note the task's demise. */
	cprintf("[PID %5u] Freed task with PID %u\n", task->killed_by,
		task->task_pid);

	/* Free the VMAs */
	free_vmas(task);

	/* Unmap the user pages. */
	unmap_user_pages(task->task_pml4);

	task->user_mem_freed = 1;

	if(task->task_type == TASK_TYPE_KERNEL) {
		DEBUG_TASK_FREE("Task %lu is a kernel task. Freeing the stack\n", task->task_pid);
		kernel_task_remove_stack(task);
	}

	task_detach_children(task, parent);

	if(task->task_type == TASK_TYPE_USER) {
		atomic_dec(&nuser_tasks);
	}

	if(parent != NULL) {
		// Remove from any parent children lists
		list_del(&task->task_child);
		list_add(&parent->task_zombies, &task->task_node);

		// Notify waiting parent
		if(parent->task_status == TASK_NOT_RUNNABLE) {
			if(parent->task_wait == NULL || parent->task_wait->task_pid == task->task_pid) {
				parent->task_wait = NULL;

				parent->task_frame.rax = task->task_pid;

				parent->task_status = TASK_RUNNABLE;
			}
		}

		spin_unlock(&parent->task_lock);
		spin_unlock(&task->task_lock);
	} else {
		DEBUG_TASK_FREE("Task %lu has NULL parent, doing final free\n", task->task_pid);
		task_final_free(task);
	}
#endif
}

void task_kill(struct task* task) {
	DEBUG_TASK_FREE("CPU %u killing task %lu\n", this_cpu->cpu_id, task->task_pid);
	assert(task->task_status == TASK_RUNNABLE || task->task_status == TASK_RUNNING || task->task_status == TASK_IN_INTERRUPT);

	task->killed = 1;

	task_destroy(task);
}

/* Frees the task. If the task is the currently running task, then this
 * function runs a new task (and does not return to the caller).
 */
void task_destroy(struct task *task)
{
	DEBUG_TASK_FREE("CPU %u destroying task %lu\n", this_cpu->cpu_id, task->task_pid);
	assert(task->task_status != TASK_DYING);
	assert(task->killed = 1);

	task->task_status = TASK_DYING;

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&global_runq_lock);
	#endif

	list_del(&task->task_node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&global_runq_lock);
	#endif

	task_free(task);

	if(task == cur_task) {
		cur_task = NULL;
		sched_start();
	}
}

/*
 * Restores the register values in the trap frame with the iretq or sysretq
 * instruction. This exits the kernel and starts executing the code of some
 * task.
 *
 * This function does not return.
 */
void task_pop_frame(struct int_frame *frame)
{
	#ifdef LAB3_SYSCALL
		switch (frame->int_no) {
			case INT_SYSCALL:
				sysret64(frame);
				break;
			default:
				iret64(frame);
				break;
		}
	#else
		iret64(frame);
	#endif

	panic("We should have gone back to userspace!");
}

/* Context switch from the current task to the provided task.
 * Note: if this is the first call to task_run(), cur_task is NULL.
 *
 * This function does not return.
 */
void task_run(struct task *task)
{
	assert(task != NULL);
	assert(task->task_status == TASK_RUNNABLE);

	DEBUG_TASK_RUN("CPU %u running task %lu\n", this_cpu->cpu_id, task->task_pid);

	/*
	 * Step 1: If this is a context switch (a new task is running):
	 *     1. Set the current task (if any) back to
	 *        TASK_RUNNABLE if it is TASK_RUNNING (think about
	 *        what other states it can be in),
	 *     2. Set 'cur_task' to the new task,
	 *     3. Set its status to TASK_RUNNING,
	 *     4. Update its 'task_runs' counter,
	 *     5. Use load_pml4() to switch to its address space.
	 * Step 2: Use task_pop_frame() to restore the task's
	 *     registers and drop into user mode in the
	 *     task.
	 *
	 * Hint: This function loads the new task's state from
	 *  e->task_frame.  Go back through the code you wrote above
	 *  and make sure you have set the relevant parts of
	 *  e->task_frame to sensible values.
	 */
	if (task != cur_task) {
		if(cur_task) {
			#ifndef USE_BIG_KERNEL_LOCK
				spin_lock(&cur_task->task_lock);
			#endif

			DEBUG_TASK_RUN("task %lu not equal to cur_task %lu\n", task->task_pid, cur_task->task_pid);

			if (cur_task->task_status == TASK_RUNNING) {
				cur_task->task_status = TASK_RUNNABLE;
			}

			sched_update_budget(cur_task);

			#ifndef USE_BIG_KERNEL_LOCK
				spin_unlock(&cur_task->task_lock);
			#endif
		} else {
			DEBUG_TASK_RUN("task %lu not equal to cur_task NULL\n", task->task_pid);
		}

		cur_task = task;
		cur_task->task_runs++;
		load_pml4((struct page_table*) PADDR(cur_task->task_pml4));
	}


	cur_task->task_cpunum = lapic_cpunum();

	#ifdef USE_BIG_KERNEL_LOCK
		cur_task->task_status = TASK_RUNNING;
		list_add(&global_runq, &cur_task->task_node);
		spin_unlock(&kernel_lock);
	#else
		cur_task->task_status = TASK_RUNNING;
		list_add(&this_cpu->nextq, &cur_task->task_node);
		spin_unlock(&cur_task->task_lock);
	#endif

	if(cur_task->task_type == TASK_TYPE_USER) {
		task_pop_frame(&cur_task->task_frame);
	} else {
		kernel_task_start(&cur_task->task_frame);
	}
}
