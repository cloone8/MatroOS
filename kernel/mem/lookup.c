#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/debug.h>

struct lookup_info {
	physaddr_t pa;
	physaddr_t* entry;
};

/* If the PTE points to a present page, store the pointer to the PTE into the
 * info struct of the walker.
 */
static int lookup_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_LOOKUP_PAGE("Looking up in PTE\n");

	struct lookup_info *info = walker->udata;

	if (*entry & PAGE_PRESENT) {
		DEBUG_LOOKUP_PAGE("Found\n");
		info->entry = entry;
		info->pa = PAGE_ADDR(*entry);
		return 0;
	} else {
		DEBUG_LOOKUP_PAGE("Not found\n");
		return -1;
	}
}

/* If the PDE points to a present huge page, store the pointer to the PDE into
 * the info struct of the walker. */
static int lookup_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_LOOKUP_PAGE("Looking up in PDE\n");

	struct lookup_info *info = walker->udata;

	if(!(*entry & PAGE_HUGE)) {
		DEBUG_LOOKUP_PAGE("PDE does not contain huge page\n");
		return 0;
	}

	DEBUG_LOOKUP_PAGE("PDE contains huge page. Finding address\n");

	if (*entry & PAGE_PRESENT) {
		info->entry = entry;
		info->pa = PAGE_ADDR(*entry);
		return 0;
	} else {
		return -1;
	}
}

/* Return the page mapped at virtual address 'va'.
 * If entry_store is not zero, then we store the address of the PTE for this
 * page into entry_store.
 * This is function can be used to verify page permissions for system call
 * arguments, but should generally not be used by most callers.
 *
 * Return NULL if there is no page mapped at va.
 *
 * Hint: this function calls walk_page_range() and pa2page().
 */
struct page_info *page_lookup(struct page_table *pml4, void *va,
    physaddr_t **entry_store)
{
	DEBUG_LOOKUP_PAGE("Looking up va %p in PML4 %p with entry store %p\n", va, pml4, entry_store);

	struct lookup_info info = {
		.pa = (physaddr_t) (-1),
		.entry = NULL
	};

	struct page_walker walker = {
		.pte_callback = lookup_pte,
		.pde_callback = lookup_pde,
		.udata = &info,
	};

	const int retval = walk_page_range(pml4, va, (void *)((uintptr_t)va + PAGE_SIZE), &walker);

	if (retval < 0 || (info.pa == (physaddr_t) (-1))) {
		DEBUG_LOOKUP_PAGE("Could not find page\n");
		return NULL;
	}

	if (entry_store != NULL) {
		*entry_store = info.entry;
	}

	DEBUG_LOOKUP_PAGE("Lookup succesful: %p -> %p\n", va, info.pa);

	return pa2page(info.pa);
}
