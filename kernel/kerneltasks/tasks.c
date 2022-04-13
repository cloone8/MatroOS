#include <atomic.h>
#include <kernel/dev/disk.h>
#include <kernel/kerneltasks.h>
#include <kernel/sched.h>
#include <stdio.h>
#include <task.h>

#ifndef USE_BIG_KERNEL_LOCK
    struct spinlock clock_list_lock = {
        #ifdef DEBUG_SPINLOCK
        .name = "clock_list_lock"
        #endif
    };

    struct spinlock swap_back_lock = {
        #ifdef DEBUG_SPINLOCK
        .name = "swap_back_lock"
        #endif
    };
#endif

// Swapping to disk
struct list clock_list;
struct list swap_infos;
uint64_t cur_swap_infos_id = 1;

// Swapping back from disk
struct list swap_back_requests;

int test_print(void) {
    int a = 1;
    int b = 2;
    int c = 3;
    int d = 4;
    int e = 5;
    int stack_array[10] = {
        1,2,3,4,5,6,7,8,9,10
    };

    cprintf("First run: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", a, b, c, d, e, stack_array[0], stack_array[1], stack_array[2], stack_array[3] ,stack_array[4], stack_array[5], stack_array[6], stack_array[7], stack_array[8], stack_array[9]);

    kernel_task_yield();

    cprintf("Second run: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\n", e, d, c, b, a, stack_array[0], stack_array[1], stack_array[2], stack_array[3] ,stack_array[4], stack_array[5], stack_array[6], stack_array[7], stack_array[8], stack_array[9]);

    cprintf("Done!\n");

    return 0;
}

int test_timer_interrupt(void) {
    while(1);

    return 0;
}

int test_pfault(void) {
    int badint = *((int*) 0xfffffffffffeffff);

    cprintf("%d\n", badint);

    return 0;
}

struct page_reclaim* page_reclaim_alloc(struct page_info* page, struct page_table* pml4, uintptr_t base_addr) {
    struct page_reclaim* pr;
    pr = kmalloc(sizeof *pr);

    if (pr == NULL) {
        return NULL;
    }

    pr->page = page;
    list_init(&pr->pr_node);
    pr->pml4 = pml4;
    pr->base_addr = base_addr;
    return pr;
}

struct pte_swap_page* pte_swap_page_alloc(physaddr_t* entry) {
    struct pte_swap_page* swap;

    swap = kmalloc(sizeof *swap);

    if (swap == NULL) {
        return NULL;
    }

    swap->entry = entry;
    list_init(&swap->entry_node);

    #ifdef DEBUG_SPINLOCK
        swap->entry_list_lock.name = "entry_list_lock";
    #endif

    return swap;
}

struct swap_list* swap_list_init(struct swap_list* swap_list) {
    swap_list = kmalloc(sizeof *swap_list);
    list_init(&swap_list->swap_infos);
    swap_list->size = 0;

    return swap_list;
}

void swap_list_insert(struct swap_list* swap_list, struct swap_info* swap_info) {
    list_add_tail(&swap_list->swap_infos, &swap_info->node);
    swap_list->size++;
}

void remove_from_ref_list(physaddr_t* entry, struct page_info* existing_page) {
    struct list* node = NULL;
    struct list* to_remove = NULL;
    struct pte_swap_page* from_page;

    list_foreach(&existing_page->pp_refs, node) {
        from_page = container_of(node, struct pte_swap_page, entry_node);
        if (from_page->entry == entry) {
            to_remove = node;
            break;
        }
    }

    if (to_remove != NULL) {
        list_del(node);
    }
}

void swap_in(void) {
    struct disk* swap_disk = disks[1];

    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&swap_back_lock);
    #endif

    if (list_is_empty(&swap_back_requests)) {
        #ifndef USE_BIG_KERNEL_LOCK
            spin_unlock(&swap_back_lock);
        #endif

        cprintf("No swap back requests\n");
        return;
    }

    struct list* request_node;
    list_foreach(&swap_back_requests, request_node) {
        struct swap_back_info* back_info = container_of(request_node, struct swap_back_info, node);

        #ifndef USE_BIG_KERNEL_LOCK
            spin_lock(&back_info->requesting_task->task_lock);
        #endif

        if(back_info->requesting_task->task_status == TASK_DYING) {
            #ifndef USE_BIG_KERNEL_LOCK
                spin_unlock(&back_info->requesting_task->task_lock);
            #endif

            continue;
        }

        struct swap_info* swap_info = NULL;

        struct list* info_node;
        list_foreach(&swap_infos, info_node) {
            struct swap_info* cur_swap_info = container_of(info_node, struct swap_info, node);

            if(cur_swap_info->id == back_info->id) {
                swap_info = cur_swap_info;
                break;
            }
        }

        assert(swap_info != NULL);

        struct page_info* new_page = page_alloc(0);

        if(!new_page) {
            #ifndef USE_BIG_KERNEL_LOCK
                spin_unlock(&back_info->requesting_task->task_lock);
                spin_unlock(&swap_back_lock);
            #endif
            return;
        }

        // Copy back from the disk
        if(disk_read(swap_disk, page2kva(new_page), N_SECTORS, (swap_info->offset_in_pages * PAGE_SIZE) / SECT_SIZE) == -EAGAIN) {

            while(!disk_poll(swap_disk)) {
                // kernel_task_yield();
            }

            if(disk_read(swap_disk, page2kva(new_page), N_SECTORS, (swap_info->offset_in_pages * PAGE_SIZE) / SECT_SIZE) != PAGE_SIZE) {
                panic("Disk was not ready or an incorrect amount of bytes was written, invalid transaction");
            }
        } else {
            panic("Disk was still busy, invalid transaction");
        }

        struct list* pte_node;
        struct list* pte_next;
        list_foreach_safe(&swap_info->ptes, pte_node, pte_next) {

            struct pte_swap_page* pte_swap_page = container_of(pte_node, struct pte_swap_page, entry_node);

            atomic_inc(&new_page->pp_ref);
            list_del(&pte_swap_page->entry_node);
            list_add(&new_page->pp_refs, &pte_swap_page->entry_node);
            *(pte_swap_page->entry) &= PAGE_MASK;
            *(pte_swap_page->entry) |= PAGE_ADDR(page2pa(new_page));
            *(pte_swap_page->entry) |= PAGE_PRESENT;

        }
		// Add to clock page reclaim queue.
		struct page_reclaim* to_reclaim = page_reclaim_alloc(new_page, back_info->requesting_task->task_pml4, back_info->base_addr);
		assert(to_reclaim != NULL);

		#ifndef USE_BIG_KERNEL_LOCK
			spin_lock(&clock_list_lock);
		#endif

		list_add(&clock_list, &to_reclaim->pr_node);

		#ifndef USE_BIG_KERNEL_LOCK
			spin_unlock(&clock_list_lock);
		#endif

        #ifndef USE_BIG_KERNEL_LOCK
            spin_unlock(&back_info->requesting_task->task_lock);
        #endif
        back_info->requesting_task->task_status = TASK_RUNNABLE;
    }

    // Remove the standing requests, as they've been handled now
    struct list* request_next;

    list_foreach_safe(&swap_back_requests, request_node, request_next) {
        struct swap_back_info* swap_back_request = container_of(request_node, struct swap_back_info, node);

        list_del(&swap_back_request->node);
        kfree(swap_back_request);
    }

    #ifndef USE_BIG_KERNEL_LOCK
        spin_unlock(&swap_back_lock);
    #endif

    return;
}

static uint64_t find_free_disk_sector(uint64_t swap_disk_size) {
    uint64_t first_free = 1;

    for(uint64_t cur_page = 1; ((cur_page * PAGE_SIZE) + PAGE_SIZE) < swap_disk_size; cur_page++) {
        int is_free = 1;

        struct list* node;
        list_foreach(&swap_infos, node) {
            struct swap_info* swap_info = container_of(node, struct swap_info, node);
            if(swap_info->offset_in_pages == cur_page) {
                is_free = 0;
                break;
            }
        }

        if(is_free) {
            first_free = cur_page;
            break;
        }
    }
    return first_free;
}

int swap_out(void) {

    struct disk* swap_disk = disks[1];

    assert(swap_disk != NULL);

    struct disk_stat swap_disk_stats;
    disk_stat(swap_disk, &swap_disk_stats);

    #ifndef USE_BIG_KERNEL_LOCK
        spin_lock(&clock_list_lock);
    #endif

    if (!list_is_empty(&clock_list)) {
        struct list* clock_node = NULL;
        struct list* to_remove = NULL;

        struct list* clock_next;
        list_foreach_safe(&clock_list, clock_node, clock_next) {
            struct page_reclaim* to_eval = container_of(clock_node, struct page_reclaim, pr_node);
            assert(to_eval != NULL);

            struct page_info* page_to_swap = to_eval->page;

            // Make sure the page wasn't freed in the meantime
            assert(page_to_swap->pp_free == 0);
            assert(page_to_swap->pp_ref > 0);
            assert(!list_is_empty(&page_to_swap->pp_refs));

            // Check if we can swap the page
            int need_to_swap = 1;

            struct list* ref_node;
            list_foreach(&page_to_swap->pp_refs, ref_node) {
                struct pte_swap_page* ref_info = container_of(ref_node, struct pte_swap_page, entry_node);
                // Second chance
                if (*ref_info->entry & PAGE_ACCESSED) {
                    *ref_info->entry &= ~(PAGE_ACCESSED);
                    need_to_swap = 0;
                }
            }

            // Place the page frame back at the beginning of the clock list
            if(!need_to_swap) {
                list_del(clock_node);
                list_add(&clock_list, clock_node);
                continue;
            }

            // We can swap this page
            struct swap_info* swap_info = kmalloc(sizeof(struct swap_info));
            assert(swap_info != NULL);

            list_init(&swap_info->ptes);
            list_init(&swap_info->node);
            swap_info->offset_in_pages = find_free_disk_sector(swap_disk_stats.nsectors * swap_disk_stats.sect_size);

            if(swap_info->offset_in_pages == 0) {
                // No more disk space, abort!
                kfree(swap_info);

                #ifndef USE_BIG_KERNEL_LOCK
                    spin_unlock(&clock_list_lock);
                #endif
                return 0;
            }

            swap_info->id = cur_swap_infos_id++;

            // Add the swap info struct in the proper place
            list_add_tail(&swap_infos, &swap_info->node);

            // Now actually swap the page to disk
            assert(disk_sector_aligned((uintptr_t) page2kva(page_to_swap)));

            if(disk_write(swap_disk, page2kva(page_to_swap), N_SECTORS, (swap_info->offset_in_pages * PAGE_SIZE) / SECT_SIZE) == -EAGAIN) {
                while(!disk_poll(swap_disk)) {
                    #ifndef USE_BIG_KERNEL_LOCK
                        spin_unlock(&clock_list_lock);
                    #endif
                    // kernel_task_yield();
                    #ifndef USE_BIG_KERNEL_LOCK
                        spin_lock(&clock_list_lock);
                    #endif
                }

                if(disk_write(swap_disk, page2kva(page_to_swap), N_SECTORS, (swap_info->offset_in_pages * PAGE_SIZE) / SECT_SIZE) != PAGE_SIZE) {
                    panic("Disk was not ready or an incorrect amount of bytes was written, invalid transaction");
                }
            }
            else {
                panic("Disk was still busy, invalid transaction");
            }

            if (!page_to_swap->pp_ref) {
                // Page was swapped out during diskwrite
                list_del(&swap_info->node);

                #ifndef USE_BIG_KERNEL_LOCK
                    spin_unlock(&clock_list_lock);
                #endif
                return 0;
            }

            // Move the PTEs and set them
            #ifdef DO_SWAP_CLEAR_PTES
            struct list* ref_next;
            list_foreach_safe(&page_to_swap->pp_refs, ref_node, ref_next) {
                struct pte_swap_page* page_ref = container_of(ref_node, struct pte_swap_page, entry_node);

                #ifndef USE_BIG_KERNEL_LOCK
                    spin_lock(&page_ref->entry_list_lock);
                #endif
                list_del(&page_ref->entry_node);
                list_add(&swap_info->ptes, &page_ref->entry_node);

                *(page_ref->entry) &= ~(PAGE_PRESENT);
                *(page_ref->entry) &= PAGE_MASK;
                *(page_ref->entry) |= PAGE_ADDR(swap_info->id << PAGE_TABLE_SHIFT);

                page_decref(page_to_swap);
                tlb_invalidate(to_eval->pml4, (void*)to_eval->base_addr);
                #ifndef USE_BIG_KERNEL_LOCK
                    spin_unlock(&page_ref->entry_list_lock);
                #endif
            }

            assert(page_to_swap->pp_free);
            #endif

            list_del(&to_eval->pr_node);
            kfree(to_eval);

            #ifndef USE_BIG_KERNEL_LOCK
                spin_unlock(&clock_list_lock);
            #endif

            return 1;
        }
    }

    #ifndef USE_BIG_KERNEL_LOCK
        spin_unlock(&clock_list_lock);
    #endif

    return 0;
}

int kswapd() {

    #ifdef USE_PAGE_SWAP
    list_init(&swap_infos);
    list_init(&swap_back_requests);

    for (;;) {
        #ifdef DO_SWAP_OUT
        int num_swapped_out = swap_out();
        #endif

        #if defined(DO_SWAP_OUT) && defined(DO_SWAP_IN)
        kernel_task_yield();
        #endif


        #ifdef DO_SWAP_IN
        swap_in();
        #endif

        if (nuser_tasks == 0) {
            kernel_task_end();
        } else {
            kernel_task_yield();
        }
    }

    #endif

    return 0;
}
