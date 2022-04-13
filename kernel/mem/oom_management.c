#include <types.h>
#include <task.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <spinlock.h>

static int calc_size_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	size_t* total_size = (size_t*) walker->udata;

    *total_size += PAGE_SIZE;

    return 0;
}

size_t get_rss(struct task* task) {
    size_t total_size = 0;

    struct page_walker walker = {
		.pte_unmap = calc_size_pte,
        .udata = (void*) &total_size
	};

	const int retval = walk_user_pages(task->task_pml4, &walker);

    assert(retval >= 0);

    return total_size;
}

struct page_info *page_alloc_with_retry(int alloc_flags) {
    struct page_info* page = page_alloc(alloc_flags);
    if(page) {
        return page;
    } else {
      if(oom() < PAGE_SIZE) {
            return NULL;
        } else {
            page = page_alloc(alloc_flags);

            return page;
        }
    }
}

size_t oom(void) {
    size_t freed = 0;
    size_t biggest_rss = 0;
    struct task* to_kill = NULL;

    for(pid_t pid = 1; pid < PID_MAX; pid++) {
        struct task* t = tasks[pid];

        if(t == NULL || t->task_type == TASK_TYPE_KERNEL || t->task_status == TASK_DYING) {
            continue;
        }

        const size_t rss = get_rss(t);

        if(rss > biggest_rss) {
            biggest_rss = rss;
            to_kill = t;
        }
    }

    if(to_kill != NULL) {
        #ifndef USE_BIG_KERNEL_LOCK
            spin_lock(&to_kill->task_lock);
        #endif

        if(to_kill->task_status != TASK_RUNNING) {
            task_kill(to_kill);
        } else {
            to_kill->killed = 1;
            to_kill->killed_by = 0;

            #ifndef USE_BIG_KERNEL_LOCK
                spin_unlock(&to_kill->task_lock);
            #endif

            // Wait for the task to be killed
            while(!to_kill->user_mem_freed);
        }
    }

    return biggest_rss;
}
