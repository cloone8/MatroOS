#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/kerneltasks.h>

#ifndef USE_BIG_KERNEL_LOCK
	extern struct spinlock clock_list_lock;
#endif

struct populate_info {
	struct page_table* pml4;
	uint64_t flags;
	uintptr_t base, end;
	int add_to_clock;
};

#define POPULATE_OOM (-1)
#define POPULATE_INSERT_ERROR (-2)

static int populate_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{

	if(*entry & PAGE_PRESENT) {
		return 0;
	}

	struct populate_info* const info = walker->udata;

	struct page_info* const page = page_alloc(ALLOC_ZERO);

	if(page == NULL) {
		return POPULATE_OOM;
	}


	const int insert_retval = page_insert(info->pml4, page, (void*) base, info->flags);

	if(insert_retval != 0) {
		page_free(page);
		return POPULATE_INSERT_ERROR;
	}
	#ifdef USE_PAGE_SWAP

		assert(&page->pp_refs != NULL);
		struct pte_swap_page *swap_page = pte_swap_page_alloc(entry);
		assert(swap_page != NULL);
		spin_lock(&swap_page->entry_list_lock);
		list_add(&page->pp_refs, &swap_page->entry_node);
		spin_unlock(&swap_page->entry_list_lock);

		if (info->add_to_clock) {
			// Add to clock page reclaim queue.
			struct page_reclaim* to_reclaim = page_reclaim_alloc(page, info->pml4, base);
			assert(to_reclaim != NULL);
			assert(&to_reclaim->pr_node != NULL);
			assert(&clock_list != NULL);

			#ifndef USE_BIG_KERNEL_LOCK
				spin_lock(&clock_list_lock);
			#endif
			*entry |= PAGE_ACCESSED;

			list_add_tail(&clock_list, &to_reclaim->pr_node);
			#ifndef USE_BIG_KERNEL_LOCK
				spin_unlock(&clock_list_lock);
			#endif

		}

	#endif

	return 0;
}

/* Populates the region [va, va + size) with pages by allocating pages from the
 * frame allocator and mapping them.
 */
void populate_region(struct page_table *pml4, void *va, size_t size,
	uint64_t flags, int add_to_clock)
{
	struct populate_info info = {
		.pml4 = pml4,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
		.add_to_clock = add_to_clock,
	};
	struct page_walker walker = {
		.pte_callback = populate_pte,
		.pde_callback = ptbl_alloc,
		.pdpte_callback = ptbl_alloc,
		.pml4e_callback = ptbl_alloc,
		.udata = &info,
	};

	int retval = walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);

	switch(retval) {
		case POPULATE_OOM:
			// Try to free memory first
			oom();
			// Retry once
			retval = walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
			if(retval != 0) {
				panic("OOM in populate_region");
			}
			break;
		case POPULATE_INSERT_ERROR:
			panic("Error in inserting page in populate_region");
			break;
		case 0:
			break;
		default:
			panic("Unknown return value");
			break;
	}

	return;
}
