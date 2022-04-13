#include <types.h>
#include <paging.h>
#include <atomic.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <kernel/kerneltasks.h>

struct insert_info {
	struct page_table *pml4;
	struct page_info *page;
	uint64_t flags;
};

/* If the PTE already points to a present page, the reference count of the page
 * gets decremented and the TLB gets invalidated. Then this function increments
 * the reference count of the new page and sets the PTE to the new page with
 * the user-provided permissions.
 */
static int insert_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct insert_info *info = walker->udata;
	struct page_info *page = info->page;

	(*entry) |= PAGE_ADDR((physaddr_t)page2pa(page));
	(*entry) |= info->flags;

	#ifdef USE_PAGE_SWAP
		if (info->flags & PAGE_USER) {
			assert(&page->pp_refs != NULL);
			struct pte_swap_page *swap_page = pte_swap_page_alloc(entry);
			assert(swap_page != NULL);
			spin_lock(&swap_page->entry_list_lock);
			list_add(&page->pp_refs, &swap_page->entry_node);
			spin_unlock(&swap_page->entry_list_lock);
		}
	#endif

	return 0;
}

/* If the PDE already points to a present huge page, the reference count of the
 * huge page gets decremented and the TLB gets invalidated. Then if the new
 * page is a 4K page, this function calls ptbl_alloc() to allocate a new page
 * table. If the new page is a 2M page, this function increments the reference
 * count of the new page and sets the PDE to the new huge page with the
 * user-provided permissions.
 */
static int insert_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct insert_info *info = walker->udata;
	struct page_info *page = info->page;

	if (info->flags & PAGE_HUGE) {
		(*entry) |= PAGE_ADDR((physaddr_t)page2pa(page));
		(*entry) |= info->flags;

		return 0;
	}

	#ifdef USE_PAGE_SWAP
		if (info->flags & PAGE_USER) {
			assert(&page->pp_refs != NULL);
			struct pte_swap_page *swap_page = pte_swap_page_alloc(entry);
			assert(swap_page != NULL);
			spin_lock(&swap_page->entry_list_lock);
			list_add(&page->pp_refs, &swap_page->entry_node);
			spin_unlock(&swap_page->entry_list_lock);
		}
	#endif

	return ptbl_alloc(entry, base, end, walker);
}


/* Map the physical page page at virtual address va. The flags argument
 * contains the permission to set for the PTE. The PAGE_PRESENT flag should
 * always be set.
 *
 * Requirements:
 *  - If there is already a page mapped at va, it should be removed using
 *    page_decref().
 *  - If necessary, a page should be allocated and inserted into the page table
 *    on demand. This can be done by providing ptbl_alloc() to the page walker.
 *  - The reference count of the page should be incremented upon a successful
 *    insertion of the page.
 *  - The TLB must be invalidated if a page was previously present at va.
 *
 * Corner-case hint: make sure to consider what happens when the same page is
 * re-inserted at the same virtual address in the same page table. However, do
 * not try to distinguish this case in your code, as this frequently leads to
 * subtle bugs. There is another elegant way to handle everything in the same
 * code path.
 *
 * Hint: what should happen when the user inserts a 2M huge page at a
 * misaligned address?
 *
 * Hint: this function calls walk_page_range(), hpage_aligned()and page2pa().
 */
int page_insert(struct page_table *pml4, struct page_info *page, void *va,
    uint64_t flags)
{
	DEBUG_INSERT_PAGE("Inserting page %p in PML4 %p at address %p with flags 0x%lx\n", page2pa(page), pml4, va, flags);

	assert(page2kva(page) != va);

	struct insert_info info = {
		.page = page,
		.flags = flags | PAGE_PRESENT
	};

	struct page_walker walker = {
		.pte_callback = insert_pte,
		.pde_callback = insert_pde,
		.pdpte_callback = ptbl_alloc,
		.pml4e_callback = ptbl_alloc,
		.udata = &info,
	};

	if (page->pp_order == BUDDY_2M_PAGE) {
		int retval = hpage_aligned((uintptr_t)va);
		if (!retval) {
			return -1;
		}
		info.flags |= PAGE_HUGE;
	}

	physaddr_t* entry;
	struct page_info* existing_page = page_lookup(pml4, va, &entry);
	DEBUG_INSERT_PAGE(existing_page == NULL ? "No existing page found\n" : "Existing page found\n");

	const int retval = walk_page_range(pml4, va, va + PAGE_SIZE, &walker);

	if(retval < 0) {
		return retval;
	}

	atomic_inc(&page->pp_ref);

	// ???
	// list_init(&page->pp_node);

	if (existing_page == page) {
		DEBUG_INSERT_PAGE("Insert done\n");
		return 0;
	}

	if (existing_page != NULL) {
		#ifdef USE_PAGE_SWAP
			remove_from_ref_list(entry, existing_page);
		#endif
		page_decref(existing_page);
		tlb_invalidate(pml4, va);
	}

	DEBUG_INSERT_PAGE("Insert done\n");

	return 0;
}
