#include <types.h>
#include <string.h>
#include <paging.h>
#include <atomic.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <kernel/kerneltasks.h>

/* Allocates a page table if none is present for the given entry.
 * If there is already something present in the PTE, then this function simply
 * returns. Otherwise, this function allocates a page using page_alloc(),
 * increments the reference count and stores the newly allocated page table
 * with the PAGE_PRESENT | PAGE_WRITE | PAGE_USER permissions.
 */
int ptbl_alloc(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_PTBL_OPS("Allocing page table for entry %p\n", entry);
	if (*entry & PAGE_PRESENT) {
		return 0;
	}

	struct page_info *page = page_alloc_with_retry(ALLOC_ZERO);
	assert_oom(page);

	atomic_inc(&page->pp_ref);
	(*entry) |= PAGE_ADDR(page2pa(page));
	(*entry) |= PAGE_PRESENT;
	(*entry) |= PAGE_WRITE;
	(*entry) |= PAGE_USER;

	DEBUG_PTBL_OPS("Done allocing page table for entry %p\n", entry);
	return 0;
}

/* Splits up a huge page by allocating a new page table and setting up the huge
 * page into smaller pages that consecutively make up the huge page.
 *
 * If no huge page was mapped at the entry, simply allocate a page table.
 *
 * Otherwise if a huge page is present, allocate a new page, increment the
 * reference count and have the PDE point to the newly allocated page. This
 * page is used as the page table. Then allocate a normal page for each entry,
 * copy over the data from the huge page and set each PDE.
 *
 * Hint: the only user of this function is boot_map_region(). Otherwise the 2M
 * physical page has to be split down into its individual 4K pages by updating
 * the respective struct page_info structs.
 *
 * Hint: this function calls ptbl_alloc(), page_alloc(), page2pa() and
 * page2kva().
 */
int ptbl_split(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_PTBL_HUGE("Splitting huge page\n");
    if ((*entry & PAGE_PRESENT) && (*entry & PAGE_HUGE)) {
		struct page_info* page = page_alloc(ALLOC_ZERO);
		atomic_inc(&page->pp_ref);

		*entry |= PAGE_ADDR(page2pa(page));

		struct page_table* p_table = (struct page_table*) page;

		for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
			struct page_info* new_page = page_alloc(ALLOC_ZERO);
			p_table->entries[i] = PAGE_ADDR(page2pa(new_page));
		}
		return 0;
    } else {
		return ptbl_alloc(entry, base, end, walker);
	}
}

/* Attempts to merge all consecutive pages in a page table into a huge page.
 *
 * First checks if the PDE points to a huge page. If the PDE points to a huge
 * page there is nothing to do. Otherwise the PDE points to a page table.
 * Then this function checks all entries in the page table to check if they
 * point to present pages and share the same flags. If not all pages are
 * present or if not all flags are the same, this function simply returns.
 * At this point the pages can be merged into a huge page. This function now
 * allocates a huge page and copies over the data from the consecutive pages
 * over to the huge page.
 * Finally, it sets the PDE to point to the huge page with the flags shared
 * between the previous pages.
 *
 * Hint: don't forget to free the page table and the previously used pages.
 */
int ptbl_merge(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
    if ((*entry & PAGE_PRESENT) && !(*entry & PAGE_HUGE)) {
        struct page_table *table = (struct page_table *)PAGE_ADDR(*entry);

        uint64_t flags = (physaddr_t)(table->entries[0]) & PAGE_MASK;
		struct page_info* huge_page = page_alloc(ALLOC_HUGE);

        for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
            physaddr_t *entry = (physaddr_t *)table->entries[i];
            if (!(*entry & PAGE_PRESENT) || (*entry & PAGE_MASK) != flags) {
				huge_page = NULL;
                return 0;
            }
			char* copy_data = page2kva(huge_page);
			memset(copy_data, i, PAGE_SIZE);
		}

		for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
            struct page_info* page = pa2page(table->entries[i]);
			page_free(page);
		}
    }

    return 0;
}

/* Frees up the page table by checking if all entries are clear. Returns if no
 * page table is present. Otherwise this function checks every entry in the
 * page table and frees the page table if no entry is set.
 *
 * Hint: this function calls pa2page(), page2kva() and page_free().
 */
int ptbl_free(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	assert(entry != NULL && ((*entry) & PAGE_PRESENT));
	struct page_info* page = pa2page(PAGE_ADDR(*entry));

	struct page_table* table = (struct page_table*) page2kva(page);

	DEBUG_PTBL_OPS("Freeing page table at %p from table entry %p\n", table, entry);
	DEBUG_PTBL_OPS("Checking if the table contains entries\n");

    for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
		physaddr_t table_entry = table->entries[i];
		if (table_entry != 0) {
			DEBUG_PTBL_OPS("Entry found at index %u. Not freeing\n", i);
			return 0;
		}
	}

	DEBUG_PTBL_OPS("No present entries found\n");

	page_decref(page);

	(*entry) = 0;
	DEBUG_PTBL_OPS("Done freeing page table\n");

	return 0;
}
