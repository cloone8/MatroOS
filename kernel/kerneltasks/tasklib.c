#include <types.h>
#include <kernel/mem.h>
#include <kernel/kerneltasks.h>
#include <kernel/sched.h>
#include <cpu.h>
#include <spinlock.h>

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock kernel_task_stack_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "kernel_task_stack_lock",
#endif
};
#endif

void kernel_task_remove_stack(struct task* kernel_task) {
    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&kernel_task_stack_lock);
    #endif

    unmap_page_range(kernel_task->task_pml4, (void*) (kernel_task->task_kern_info->init_stack_top - (KSTACK_SIZE + KSTACK_GAP)), KSTACK_SIZE + KSTACK_GAP);

    #ifndef USE_BIG_KERNEL_LOCK
        spin_unlock(&kernel_task_stack_lock);
    #endif
}

void* kernel_task_alloc_stack(struct page_table* task_pml4) {

    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&kernel_task_stack_lock);
    #endif

    const size_t kstack_total_size = KSTACK_SIZE + KSTACK_GAP;

    const uintptr_t cpu_kstack_bot = KSTACK_TOP - (ncpus * (kstack_total_size));

    uintptr_t kernel_task_kstack_top = cpu_kstack_bot;

    while(page_lookup(task_pml4, (void*) kernel_task_kstack_top, NULL)) {
        kernel_task_kstack_top -= kstack_total_size;
    }

    for(uintptr_t va = kernel_task_kstack_top - kstack_total_size; va < kernel_task_kstack_top; va += PAGE_SIZE) {
		struct page_info* page = page_alloc_with_retry(ALLOC_ZERO);

        assert_oom(page);

		const int retval = page_insert(task_pml4, page, (void*) va, PAGE_WRITE | PAGE_NO_EXEC);
		assert(retval >= 0);
	}

    #ifndef USE_BIG_KERNEL_LOCK
        spin_unlock(&kernel_task_stack_lock);
    #endif

    return (void*) kernel_task_kstack_top;
}

void kernel_task_main(int (*task_main)(void)) {
	int retval = task_main();

    kernel_task_end();
}

void kernel_task_post_end(void) {
    assert(cur_task);
    assert(cur_task->task_type == TASK_TYPE_KERNEL);

    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&cur_task->task_lock);
    #endif

    cur_task->killed = 1;
    cur_task->killed_by = 0;

    task_destroy(cur_task);
}

void kernel_task_post_yield(struct int_frame* frame) {
    assert(cur_task);
    assert(cur_task->task_type == TASK_TYPE_KERNEL);

    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&cur_task->task_lock);
    #endif

    cur_task->task_frame = *frame;
    frame = &cur_task->task_frame;

    cprintf("IP in frame: %p\n", frame->rip);

    ktask_sys_yield();
}
