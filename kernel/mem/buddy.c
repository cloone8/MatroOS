#include <types.h>
#include <list.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>
#include <atomic.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <kernel/kerneltasks.h>

/* Physical page metadata. */
size_t npages;
struct page_info *pages;
extern struct list page_zero_thread;

/*
 * List of free buddy chunks (often also referred to as buddy pages or simply
 * pages). Each order has a list containing all free buddy chunks of the
 * specific buddy order. Buddy orders go from 0 to BUDDY_MAX_ORDER - 1
 */
struct list buddy_free_list[BUDDY_MAX_ORDER];

/*
 * Find the buddy page given an address.
 */
static __always_inline struct page_info *get_buddy_from_page(struct page_info* page, uint8_t order) {
    uint64_t b_addr = page2pa(page) ^ ((1 << order) * PAGE_SIZE);
    return pa2page(b_addr);
}

#ifndef USE_BIG_KERNEL_LOCK
/* Lock for the buddy allocator. */
struct spinlock buddy_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "buddy_lock",
#endif
};
#endif

/* Counts the number of free pages for the given order.
 */
size_t count_free_pages(size_t order)
{
	struct list *node;
	size_t nfree_pages = 0;

	if (order >= BUDDY_MAX_ORDER) {
		return 0;
	}

	list_foreach(buddy_free_list + order, node) {
		atomic_inc(&nfree_pages);
	}

	return nfree_pages;
}

/* Shows the number of free pages in the buddy allocator as well as the amount
 * of free memory in kiB.
 *
 * Use this function to diagnose your buddy allocator.
 */
void show_buddy_info(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&buddy_lock);
	#endif

	cprintf("Buddy allocator:\n");

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);

		cprintf("  order #%u pages=%u\n", order, nfree_pages);

		nfree += nfree_pages * (1 << (order + 12));
	}

	cprintf("  free: %u kiB\n", nfree / 1024);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&buddy_lock);
	#endif
}

/* Gets the total amount of free pages. */
size_t count_total_free_pages(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);
		nfree += nfree_pages * (1 << order);
	}

	return nfree;
}

/* Splits lhs into free pages until the order of the page is the requested
 * order req_order.
 *
 * Returns a page of the requested order.
 */
 struct page_info *buddy_split(struct page_info *page, size_t req_order)
{
	assert(page->pp_free);
	assert(req_order < BUDDY_MAX_ORDER);

	while(page->pp_order > req_order) {
		// Locate the page's buddy at order - 1
		struct page_info* buddy = get_buddy_from_page(page, page->pp_order - 1);

		assert(buddy->pp_order == page->pp_order - 1);

		// Mark the buddy as free
		buddy->pp_free = 1;
		list_add(buddy_free_list + buddy->pp_order, &buddy->pp_node);

		// Decrement the order of the page
		page->pp_order--;

		assert(page->pp_order == buddy->pp_order);
	}

	assert(page->pp_order == req_order);
	return page;
}

/* Merges the buddy of the page with the page if the buddy is free to form
 * larger and larger free pages until either the maximum order is reached or
 * no free buddy is found.
 *
 * Returns the largest merged free page possible.
 */
struct page_info *buddy_merge(struct page_info *page)
{
	assert(page->pp_free);
	// Repeat until maximum possible order has been reached
	while (page->pp_order < (BUDDY_MAX_ORDER - 1)) {
		// Locate the page with the lowest address and its buddy of order k
		struct page_info* buddy = get_buddy_from_page(page, page->pp_order);
		struct page_info* lhs;
		struct page_info* rhs;

		if(page < buddy) {
			lhs = page;
			rhs = buddy;
		} else {
			lhs = buddy;
			rhs = page;
		}

		assert(page != buddy);

		// Check if both the page and the buddy are free and whether the order matches
		if (!(lhs->pp_free && rhs->pp_free) || !(lhs->pp_order == rhs->pp_order)) {
			break;
		}

		// Remove the page and its buddy from the free list
		list_del(&lhs->pp_node);
		list_del(&rhs->pp_node);

		// Increment the order of the page
		lhs->pp_order++;
		rhs->pp_free = 0;

		page = lhs;
	}

	return page;
}


/* Given the order req_order, attempts to find a page of that order or a larger
 * order in the free list. In case the order of the free page is larger than the
 * requested order, the page is split down to the requested order using
 * buddy_split().
 *
 * Returns a page of the requested order or NULL if no such page can be found.
 */
struct page_info *buddy_find(size_t req_order)
{
	struct list* free_page;

	// Check if we have free pages of the exact proper size
	if(!list_is_empty(buddy_free_list + req_order)) {
		return container_of(list_pop(buddy_free_list + req_order), struct page_info, pp_node);
	}

	// No pages found of the exact size. Try to split larger pages
	for(size_t order = req_order; order < BUDDY_MAX_ORDER; order++) {
		if(!list_is_empty(buddy_free_list + order)) {
			return buddy_split(container_of(list_pop(buddy_free_list + order), struct page_info, pp_node), req_order);
		}
	}

	return NULL;
}

/*
 * Allocates a physical page.
 *
 * if (alloc_flags & ALLOC_ZERO), fills the entire returned physical page with
 * '\0' bytes.
 * if (alloc_flags & ALLOC_HUGE), returns a huge physical 2M page.
 *
 * Beware: this function does NOT increment the reference count of the page -
 * this is the caller's responsibility.
 *
 * Returns NULL if out of free memory.
 *
 * Hint: use buddy_find() to find a free page of the right order.
 * Hint: use page2kva() and memset() to clear the page.
 */
struct page_info *page_alloc(int alloc_flags)
{
	struct page_info* to_return;
	size_t req_order = 0;

	#if defined(BONUS_LAB1) || defined(BONUS_LAB2)
		// Set the req order to 9 (2MB) if huge pages are supported
		if(alloc_flags & ALLOC_HUGE) {
			req_order = 9;
		}
	#endif

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&buddy_lock);
	#endif

	// Get the actual page from the buddy allocator
	to_return = buddy_find(req_order);

	// If the poison has been tainted, we know there was a use after free.
	#ifdef BONUS_LAB1
		for (size_t i = 0; i < (PAGE_SIZE * (1 << to_return->pp_order)); i++) {
			char posion = *(char*)(page2kva(to_return) + i);
			assert(posion == 'P');
		}
	#endif

	if(to_return == NULL) {
		#ifndef USE_BIG_KERNEL_LOCK
			spin_unlock(&buddy_lock);
		#endif
		return NULL;
	}

	// Remove it from the free list
	to_return->pp_free = 0;
	list_del(&to_return->pp_node);

	// The page is now marked as deallocated, so it's safe to unlock buddy
	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&buddy_lock);
	#endif

	if(alloc_flags & ALLOC_ZERO) {
		// Clear the requested page
		uint8_t* bytes = page2kva(to_return);
		size_t num_bytes = (1 << req_order) * PAGE_SIZE;
		memset(bytes, 0, num_bytes);
	}

	return to_return;
}

/*
 * Return a page to the free list.
 * (This function should only be called when pp->pp_ref reaches 0.)
 *
 * Hint: mark the page as free and use buddy_merge() to merge the free page
 * with its buddies before returning the page to the free list.
 */
void page_free(struct page_info *pp)
{
	#if defined(DEBUG_MODE) || defined(BONUS_LAB1)
		assert(pp->pp_ref == 0);
		assert(!pp->pp_free);
		assert(list_is_empty(&pp->pp_node));
	#endif

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(&buddy_lock);
	#endif

    // Mark the page as free
    pp->pp_free = 1;


    // Merge the buddy page
    pp = buddy_merge(pp);

	// Sanity check
	assert(pp->pp_order < BUDDY_MAX_ORDER);
	assert(pp->pp_free);

	// Add the page to the free list
	list_add(buddy_free_list+pp->pp_order, &pp->pp_node);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&buddy_lock);
	#endif

	// Add poison to freed memory to keep track of use-after-frees.
	#ifdef BONUS_LAB1
        memset(page2kva(pp), 'P', (1 << pp->pp_order) * PAGE_SIZE);
	#endif
}

/*
 * Decrement the reference count on a page,
 * freeing it if there are no more refs.
 */
void page_decref(struct page_info *pp)
{
	atomic_dec(&pp->pp_ref);
	if (pp->pp_ref == 0) {
		page_free(pp);
	}
}

static int in_page_range(void *p)
{
	return ((uintptr_t)pages <= (uintptr_t)p &&
	        (uintptr_t)p < (uintptr_t)(pages + npages));
}

static void *update_ptr(void *p)
{
	if (!in_page_range(p))
		return p;

	return (void *)((uintptr_t)p + KPAGES - (uintptr_t)pages);
}

void buddy_migrate(void)
{
	struct page_info *page;
	struct list *node;
	size_t i;

	for (i = 0; i < npages; ++i) {
		page = pages + i;
		node = &page->pp_node;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		node = buddy_free_list + i;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	pages = (struct page_info *)KPAGES;
}

int buddy_map_chunk(struct page_table *pml4, size_t index)
{
	DEBUG_PAGE_EXT("Entering buddy_map_chunk\n");
	struct page_info *page, *base;
	void *end;
	size_t nblocks = (1 << (12 + BUDDY_MAX_ORDER - 1)) / PAGE_SIZE;
	size_t nalloc = ROUNDUP(nblocks * sizeof *page, PAGE_SIZE) / PAGE_SIZE;
	size_t i;

	DEBUG_PAGE_EXT("Allocing %lu blocks in %lu pages\n", nblocks, nalloc);

	index = ROUNDDOWN(index, nblocks);
	base = pages + index;

	DEBUG_PAGE_EXT("Base pointer (from index %lu) is %p\n", index, base);

	for (i = 0; i < nalloc; ++i) {
		DEBUG_PAGE_EXT("Allocing %lu from %lu\n", i + 1, nalloc);
		page = page_alloc(ALLOC_ZERO);

		if (!page) {
			return -1;
		}

		DEBUG_PAGE_EXT("Inserting %lu from %lu at address %p\n", i + 1, nalloc, base + i * PAGE_SIZE);
		if (page_insert(pml4, page, (char *)base + i * PAGE_SIZE,
		    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC) < 0) {
			return -1;
		}

		DEBUG_PAGE_EXT("Done with page %lu from %lu\n", i + 1, nalloc);
	}

	DEBUG_PAGE_EXT("Initialising list nodes\n");
	for (i = 0; i < nblocks; ++i) {
		page = base + i;
		list_init(&page->pp_node);
	}

	DEBUG_PAGE_EXT("Done. Incrementing npages to %lu\n", index + nblocks);
	npages = index + nblocks;

	DEBUG_PAGE_EXT("Leaving buddy_map_chunk\n");
	return 0;
}
