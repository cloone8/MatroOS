#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/sched.h>
#include <kernel/kerneltasks.h>
#include <spinlock.h>

struct swap_back_page_info {
	struct task* requesting_task;
	int returned;
};

static int check_swapping(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker) {
	struct swap_back_page_info* walker_info = (struct swap_back_page_info*) walker->udata;
	walker_info->returned = 0;

	if(*entry & PAGE_PRESENT) {
		return 0;
	}

	if(PAGE_ADDR(*entry) == 0) {
		return 0;
	}

	const size_t swap_info_id = PAGE_ADDR(*entry) >> PAGE_TABLE_SHIFT;

	struct swap_back_info* info = kmalloc(sizeof(struct swap_back_info));
	assert(info != NULL);

	info->id = swap_info_id;
	info->requesting_task = walker_info->requesting_task;
	info->base_addr = base;

	list_init(&info->node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&swap_back_lock);
	#endif

	list_add(&swap_back_requests, &info->node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&swap_back_lock);
	#endif

	walker_info->returned = 1;
	return 0;
}

int swap_back_page(struct task* task, void* faulting_page) {
	struct swap_back_page_info swap_back_info = {
		.requesting_task = task,
		.returned = 0
	};

	struct page_walker walker = {
		.pte_callback = check_swapping,
		.udata = (void*) &swap_back_info
	};

	const int retval = walk_page_range(task->task_pml4, faulting_page, faulting_page + PAGE_SIZE, &walker);

	if(retval < 0) {
		panic("Error in swap walker");
	} else {
		return swap_back_info.returned;
	}
}

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	struct vma* vma_found = task_find_vma(task, va);
	// No VMA mapped here at all. Definitely an error
	if(!vma_found) {
		return -1;
	}

	// Find the page VA containing this virtual address
	void* faulting_page = (void*) ROUNDDOWN((uintptr_t) va, PAGE_SIZE);

	const int swapping_back = swap_back_page(task, faulting_page);

	// Wait for the task to be swapped back
	if(swapping_back == 1) {
		cprintf("Need to swap back for task %lu\n", task->task_pid);
		task->task_status == TASK_SWAPPING;

		#ifndef USE_BIG_KERNEL_LOCK
			spin_unlock(&task->task_lock);
		#endif

		sched_start();
	}

	// Populate exactly one page, the one containing this VADDR
	const int retval = populate_vma_range(task, faulting_page, PAGE_SIZE, flags);

	return retval;
}
