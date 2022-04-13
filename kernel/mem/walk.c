#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/debug.h>

/* Given an address addr, this function returns the sign extended address. */
static uintptr_t sign_extend(uintptr_t addr)
{
	return (addr < USER_LIM) ? addr : (0xffff000000000000ull | addr);
}

/* Given an addresss addr, this function returns the page boundary. */
static uintptr_t ptbl_end(uintptr_t addr)
{
	return addr | (PAGE_SIZE - 1);
}

/* Given an address addr, this function returns the page table boundary. */
static uintptr_t pdir_end(uintptr_t addr)
{
	return addr | (PAGE_TABLE_SPAN - 1);
}

/* Given an address addr, this function returns the page directory boundary. */
static uintptr_t pdpt_end(uintptr_t addr)
{
	return addr | (PAGE_DIR_SPAN - 1);
}

/* Given an address addr, this function returns the PDPT boundary. */
static uintptr_t pml4_end(uintptr_t addr)
{
	return addr | (PDPT_SPAN - 1);
}

/* Walks over the page range from base to end iterating over the entries in the
 * given page table ptbl. The user may provide walker->pte_callback() that gets
 * called for every entry in the page table. In addition the user may provide
 * walker->pt_hole_callback() that gets called for every unmapped entry in the page
 * table.
 *
 * Hint: this function calls ptbl_end() to get the end boundary of the current
 * page.
 * Hint: the next page is at ptbl_end() + 1.
 * Hint: the loop condition is next < end.
 */
static int ptbl_walk_range(struct page_table *ptbl, uintptr_t base,
    uintptr_t end, struct page_walker *walker)
{
    DEBUG_WALKER("PTBL (%p) walking range: %p -> %p\n", ptbl, base, end);
    assert(base < end);

    uintptr_t pte_start = base;

    while (pte_start < end) {
        const uintptr_t pte_end = MIN(ptbl_end(pte_start), end);
        physaddr_t *pte = ptbl->entries + PAGE_TABLE_INDEX(pte_start);

        // Always call the main callback
        if (walker->pte_callback) {
            const int retval =
                walker->pte_callback(pte, pte_start, pte_end, walker);

            if (retval < 0) {
                return retval;
            }
        }

        const physaddr_t mask = *pte & PAGE_MASK;

        if (mask & PAGE_PRESENT) {
            // Call the unmap callback function
            if (walker->pte_unmap) {
                const int retval =
                    walker->pte_unmap(pte, pte_start, pte_end, walker);

                if (retval < 0) {
                    return retval;
                }
            }
        } else if (walker->pt_hole_callback) {
            // Call the "missing" callback
            const int retval =
                walker->pt_hole_callback(pte_start, pte_end, walker);

            if (retval < 0) {
                return retval;
            }
        }

        pte_start = ptbl_end(pte_start) + 1;

        // Special case due to overflow at the 64bit memory limit
        if(pte_start == 0) {
            break;
        }
	}

	return 0;
}

/* Walks over the page range from base to end iterating over the entries in the
 * given page directory pdir. The user may provide walker->pde_callback() that gets
 * called for every entry in the page directory. In addition the user may
 * provide walker->pt_hole_callback() that gets called for every unmapped entry in the
 * page directory. If the PDE is present, but not a huge page, this function
 * calls ptbl_walk_range() to iterate over the entries in the page table. The
 * user may provide walker->pde_unmap() that gets called for every present PDE
 * after walking over the page table.
 *
 * Hint: see ptbl_walk_range().
 */
static int pdir_walk_range(struct page_table *pdir, uintptr_t base,
    uintptr_t end, struct page_walker *walker)
{
    DEBUG_WALKER("PDIR (%p) walking range: %p -> %p\n", pdir, base, end);

    assert(base < end);

    uintptr_t ptbl_start = base;

    while (ptbl_start < end) {
        const uintptr_t ptbl_end = MIN(pdir_end(ptbl_start), end);
        physaddr_t *pde = pdir->entries + PAGE_DIR_INDEX(ptbl_start);

        if (walker->pde_callback) {
            int retval =
                walker->pde_callback(pde, ptbl_start, ptbl_end, walker);
            if (retval < 0) {
                return retval;
            }
        }

        struct page_table *ptbl_entry = (struct page_table *) KADDR(PAGE_ADDR(*pde));
        const physaddr_t mask = *pde & PAGE_MASK;

        if (mask & PAGE_PRESENT) {
            // Continue walk
            int retval =
                ptbl_walk_range(ptbl_entry, ptbl_start, ptbl_end, walker);
            if (retval < 0) {
                return retval;
            }

            // Unmap callback
            if (walker->pde_unmap) {
                int retval =
                    walker->pde_unmap(pde, ptbl_start, ptbl_end, walker);

                if (retval < 0) {
                    return retval;
                }
            }
        } else if (walker->pt_hole_callback) {
            // Missing entry
            int retval = walker->pt_hole_callback(ptbl_start, ptbl_end, walker);

            if (retval < 0) {
                return retval;
            }
        }

        ptbl_start = pdir_end(ptbl_start) + 1;

        // Special case due to overflow at the 64bit memory limit
        if(ptbl_start == 0) {
            break;
        }
	}

	return 0;
}

/* Walks over the page range from base to end iterating over the entries in the
 * given PDPT pdpt. The user may provide walker->pdpte_callback() that gets called
 * for every entry in the PDPT. In addition the user may provide
 * walker->pt_hole_callback() that gets called for every unmapped entry in the PDPT. If
 * the PDPTE is present, but not a large page, this function calls
 * pdir_walk_range() to iterate over the entries in the page directory. The
 * user may provide walker->pdpte_unmap() that gets called for every present
 * PDPTE after walking over the page directory.
 *
 * Hint: see ptbl_walk_range().
 */
static int pdpt_walk_range(struct page_table *pdpt, uintptr_t base,
    uintptr_t end, struct page_walker *walker)
{
    DEBUG_WALKER("PDPT (%p) walking range: %p -> %p\n", pdpt, base, end);
    assert(base < end);

    uintptr_t pdir_start = base;

    while (pdir_start < end) {
        const uintptr_t pdir_end = MIN(pdpt_end(pdir_start), end);
        physaddr_t *pdpte = pdpt->entries + PDPT_INDEX(pdir_start);

        // Always call the main callback
        if (walker->pdpte_callback) {
            const int retval =
                walker->pdpte_callback(pdpte, pdir_start, pdir_end, walker);

            if (retval < 0) {
                return retval;
            }
        }

        struct page_table *pdir = (struct page_table *) KADDR(PAGE_ADDR(*pdpte));
        const physaddr_t mask = *pdpte & PAGE_MASK;

        if (mask & PAGE_PRESENT) {
            // Continue the walk
            int retval = pdir_walk_range(pdir, pdir_start, pdir_end, walker);

            if (retval < 0) {
                return retval;
            }

            // Call the unmap callback function
            if (walker->pdpte_unmap) {
                retval =
                    walker->pdpte_unmap(pdpte, pdir_start, pdir_end, walker);

                if (retval < 0) {
                    return retval;
                }
            }
        } else if (walker->pt_hole_callback) {
            // Call the "missing" callback
            const int retval =
                walker->pt_hole_callback(pdir_start, pdir_end, walker);

            if (retval < 0) {
                return retval;
            }
        }

        pdir_start = pdpt_end(pdir_start) + 1;

        // Special case due to overflow at the 64bit memory limit
        if(pdir_start == 0) {
            break;
        }
	}

	return 0;
}

/* Walks over the page range from base to end iterating over the entries in the
 * given PML4 pml4. The user may provide walker->pml4e_callback() that gets called
 * for every entry in the PML4. In addition the user may provide
 * walker->pt_hole_callback() that gets called for every unmapped entry in the PML4. If
 * the PML4E is present, this function calls pdpt_walk_range() to iterate over
 * the entries in the PDPT. The user may provide walker->pml4e_unmap() that
 * gets called for every present PML4E after walking over the PDPT.
 *
 * Hint: see ptbl_walk_range().
 */
static int pml4_walk_range(struct page_table *pml4, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	assert(base < end);

	uintptr_t pdpt_start = sign_extend(base);
    const uintptr_t walk_end = sign_extend(end);

    DEBUG_WALKER("PML4 (%p) walking range: %p -> %p\n", pml4, pdpt_start, walk_end);

	while (pdpt_start < walk_end) {
		const uintptr_t pdpt_end = MIN(pml4_end(pdpt_start), walk_end);
		physaddr_t* pml4e = pml4->entries + PML4_INDEX(pdpt_start);

		// Always call the main callback
		if(walker->pml4e_callback) {
			const int retval = walker->pml4e_callback(pml4e, pdpt_start, pdpt_end, walker);

			if(retval < 0) {
				return retval;
			}
		}

		struct page_table* pdpt = (struct page_table*) KADDR(PAGE_ADDR(*pml4e));
		const physaddr_t mask = *pml4e & PAGE_MASK;

		if(mask & PAGE_PRESENT) {

			// Continue the walk
			int retval = pdpt_walk_range(pdpt, pdpt_start, pdpt_end, walker);

			if(retval < 0) {
				return retval;
			}

			// Call the unmap callback
			if(walker->pml4e_unmap) {
				retval = walker->pml4e_unmap(pml4e, pdpt_start, pdpt_end, walker);

				if(retval < 0) {
					return retval;
				}
			}
		} else if(walker->pt_hole_callback) {
			// Call the "missing" callback
			const int retval = walker->pt_hole_callback(pdpt_start, pdpt_end, walker);

			if(retval < 0) {
				return retval;
			}
		}

		pdpt_start = sign_extend(pml4_end(pdpt_start) + 1);

        // Special case due to overflow at the 64bit memory limit
        if(pdpt_start == 0) {
            break;
        }
	}

	return 0;
}

/* Helper function to walk over a page range starting at base and ending before
 * end.
 */
int walk_page_range(struct page_table *pml4, void *base, void *end,
	struct page_walker *walker)
{
	return pml4_walk_range(pml4, ROUNDDOWN((uintptr_t)base, PAGE_SIZE),
		ROUNDUP((uintptr_t)end, PAGE_SIZE) - 1, walker);
}

/* Helper function to walk over all pages. */
int walk_all_pages(struct page_table *pml4, struct page_walker *walker)
{
	return pml4_walk_range(pml4, 0, KERNEL_LIM, walker);
}

/* Helper function to walk over all user pages. */
int walk_user_pages(struct page_table *pml4, struct page_walker *walker)
{
	return pml4_walk_range(pml4, 0, USER_LIM, walker);
}

/* Helper function to walk over all kernel pages. */
int walk_kernel_pages(struct page_table *pml4, struct page_walker *walker)
{
	return pml4_walk_range(pml4, KERNEL_VMA, KERNEL_LIM, walker);
}
