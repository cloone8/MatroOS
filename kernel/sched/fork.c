#include <cpu.h>
#include <error.h>
#include <list.h>
#include <atomic.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>
#include <kernel/kerneltasks.h>


#ifndef USE_BIG_KERNEL_LOCK
extern struct spinlock global_runq_lock;
#endif

struct vma_copy_udata {
	struct task* orig;
	struct task* clone;
};

extern struct list global_runq;

static int do_pte_copy(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker) {
	physaddr_t* entry_to_clone = (physaddr_t*) walker->udata;

	const physaddr_t entry_to_copy_flags = (*entry_to_clone) & PAGE_UMASK;

	const physaddr_t new_copy_entry_flags = PAGE_PRESENT | PAGE_USER | (entry_to_copy_flags & PAGE_NO_EXEC);
	const physaddr_t entry_pa = PAGE_ADDR(*entry_to_clone);

	struct page_info* page = pa2page(entry_pa);

	// Increment the physical page refcount
	atomic_inc(&page->pp_ref);

	// Insert the page at the same VA in the new process
	*entry = new_copy_entry_flags | entry_pa;

	// The page is in use, so we can use pp_node to keep a list of PTE's.
	#ifdef USE_PAGE_SWAP
		assert(&page->pp_refs != NULL);
		struct pte_swap_page* swap_page = pte_swap_page_alloc(entry);
		assert(swap_page != NULL);
		spin_lock(&swap_page->entry_list_lock);
		list_add(&page->pp_refs, &swap_page->entry_node);
		spin_unlock(&swap_page->entry_list_lock);
	#endif

	// Make the old entry non-writable for the COW page fault handler
	const physaddr_t new_orig_entry_flags = entry_to_copy_flags & ~PAGE_WRITE;

	*entry_to_clone = new_orig_entry_flags | entry_pa;

	return 0;
}

static int do_vma_copy(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker) {
	struct vma_copy_udata* udata = (struct vma_copy_udata*) walker->udata;

	struct page_walker clone_walker = {
		.pte_callback = do_pte_copy,
		.pde_callback = ptbl_alloc,
		.pdpte_callback = ptbl_alloc,
		.pml4e_callback = ptbl_alloc,
		.udata = (void*) entry
	};

	const int retval = walk_page_range(udata->clone->task_pml4, (void*)base, (void*)end, &clone_walker);

	tlb_invalidate(udata->orig->task_pml4, (void*)base);

	return retval;
}

static void do_clone_vma_copy(struct task* task, struct task* clone, struct vma* vma) {
	struct vma_copy_udata udata = {
		.orig = task,
		.clone = clone
	};

	struct page_walker walker = {
		.pte_unmap = do_vma_copy, // Use unmap because the order doesn't really matter,
								  // and unmap only gets called for existing entries
		.udata = (void*) &udata
	};

	const int retval = walk_page_range(task->task_pml4, vma->vm_base, vma->vm_end, &walker);

	assert(retval >= 0);
}

/* Allocates a task struct for the child process and copies the register state,
 * the VMAs and the page tables. Once the child task has been set up, it is
 * added to the run queue.
 */
struct task *task_clone(struct task *task)
{
	assert(task->task_type == TASK_TYPE_USER);

	struct task *clone = task_alloc(task->task_pid);

	if(clone == NULL) {
		return NULL;
	}

	atomic_inc(&nuser_tasks);

	memcpy(&clone->task_frame, &task->task_frame, sizeof(struct int_frame));

	struct list* vma_node;

	// Copy all the VMAs
	list_foreach(&task->task_mmap, vma_node) {
		struct vma* const task_vma = container_of(vma_node, struct vma, vm_mmap);

		struct vma* const returned_vma = add_executable_vma(clone, task_vma->vm_name, task_vma->vm_base, task_vma->vm_end - task_vma->vm_base, task_vma->vm_flags, task_vma->vm_src, task_vma->vm_len);

		assert(returned_vma != NULL);

		do_clone_vma_copy(task, clone, returned_vma);
	}

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&global_runq_lock);
	#endif

	list_add(&global_runq, &clone->task_node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&global_runq_lock);
	#endif

	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task* child = task_clone(cur_task);

	if(child == NULL) {
		return -1;
	}

	child->task_frame.rax = 0;

	return child->task_pid;
}
