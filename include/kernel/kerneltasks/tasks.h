#pragma once

int test_print(void);
int test_timer_interrupt(void);
int test_pfault(void);
int kswapd(void);
void remove_from_ref_list(physaddr_t* entry, struct page_info* existing_page);
struct page_reclaim* page_reclaim_alloc(struct page_info* page, struct page_table* pml4, uintptr_t base_addr);
struct pte_swap_page* pte_swap_page_alloc(physaddr_t* entry);

#ifndef USE_BIG_KERNEL_LOCK
	extern struct spinlock clock_list_lock;
	extern struct spinlock swap_back_lock;
#endif

extern struct list clock_list;
extern struct list swap_back_requests;
