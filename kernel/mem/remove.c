#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <kernel/kerneltasks.h>
#include <spinlock.h>

struct remove_info {
	struct page_table *pml4;
	int do_decref;
};

static void remove_from_clock_list(struct page_info* page) {
	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&clock_list_lock);
	#endif

	struct list* node;
	struct list* next;

	list_foreach_safe(&clock_list, node, next) {
		struct page_reclaim* to_remove = container_of(node, struct page_reclaim, pr_node);

		if(to_remove->page == page) {
			list_del(&to_remove->pr_node);
			kfree(to_remove);
			break;
		}
	}

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&clock_list_lock);
	#endif
}

/* Removes the page if present by decrement the reference count, clearing the
 * PTE and invalidating the TLB.
 */
static int remove_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_REMOVE_PAGE("Removing page from PTE %p\n at %p -> %p\n", entry, base, end);

	if(!(*entry & PAGE_PRESENT)) {
		DEBUG_REMOVE_PAGE("Page not present\n");
		return 0;
	}

	DEBUG_REMOVE_PAGE("Page present. Freeing\n");

	struct remove_info *info = walker->udata;
	struct page_info *page = pa2page(PAGE_ADDR(*entry));

	if(info->do_decref) {
		#ifdef USE_PAGE_SWAP
			remove_from_ref_list(entry, page);
			remove_from_clock_list(page);
		#endif
		page_decref(page);
	}

	tlb_invalidate(info->pml4, (void*) base);

	(*entry) = 0;

	DEBUG_REMOVE_PAGE("Done\n");
	return 0;
}

/* Removes the page if present and if it is a huge page by decrementing the
 * reference count, clearing the PDE and invalidating the TLB.
 */
static int remove_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_REMOVE_PAGE("Removing huge page from PTE %p\n at %p -> %p\n", entry, base, end);
	if ((*entry & PAGE_PRESENT) && (*entry & PAGE_HUGE)) {
		DEBUG_REMOVE_PAGE("Huge page present. Freeing\n");

		struct remove_info *info = walker->udata;
		struct page_info *page = pa2page(PAGE_ADDR(*entry));

		if(info->do_decref) {
			#ifdef USE_PAGE_SWAP
				remove_from_ref_list(entry, page);
				remove_from_clock_list(page);
			#endif
			page_decref(page);
		}
		tlb_invalidate(info->pml4, (void*) base);

		(*entry) = 0;
		ptbl_split(entry, base, end, walker);

		DEBUG_REMOVE_PAGE("Done\n");
		return 0;
	}
	DEBUG_REMOVE_PAGE("Huge page not present or huge\n");
	return 0;
}

/* Unmaps the range of pages from [va, va + size). */
void unmap_page_range(struct page_table *pml4, void *va, size_t size)
{
	struct remove_info info = {
		.pml4 = pml4,
		.do_decref = 1
	};

	struct page_walker walker = {
		.pte_callback = remove_pte,
		.pde_callback = remove_pde,
		.pml4e_unmap = ptbl_free,
		.pdpte_unmap = ptbl_free,
		.pde_unmap = ptbl_free,
		.udata = &info,
	};

	const int retval = walk_page_range(pml4, va, va + size, &walker);

	assert(retval >= 0);
}

/* Unmaps all user pages. */
void unmap_user_pages(struct page_table *pml4)
{
	unmap_page_range(pml4, 0, USER_LIM);
}

/* Unmaps the physical page at the virtual address va. */
void page_remove(struct page_table *pml4, void *va)
{
	unmap_page_range(pml4, va, PAGE_SIZE);
}

void unmap_no_decref_page_range(struct page_table *pml4, void *va, size_t size)
{
	struct remove_info info = {
		.pml4 = pml4,
		.do_decref = 0
	};

	struct page_walker walker = {
		.pte_callback = remove_pte,
		.pde_callback = remove_pde,
		.pml4e_unmap = ptbl_free,
		.pdpte_unmap = ptbl_free,
		.pde_unmap = ptbl_free,
		.udata = &info,
	};

	const int retval = walk_page_range(pml4, va, va + size, &walker);

	assert(retval >= 0);
}
