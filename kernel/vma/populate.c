#include <types.h>
#include <atomic.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/kerneltasks.h>


/* Checks the flags in udata against the flags of the VMA to check appropriate
 * permissions. If the permissions are all right, this function populates the
 * address range [base, base + size) with physical pages. If the VMA is backed
 * by an executable, the data is copied over. Then the protection of the
 * physical pages is adjusted to match the permissions of the VMA.
 */
int do_populate_vma(struct task *task, void *base, size_t size,
	struct vma *vma, void *udata)
{
	const int vma_flags = vma->vm_flags;
	const int udata_flags = *(int *)(udata);

	// If fault was caused by an access violation, throw an error
	if(udata_flags & PF_PRESENT) {
		if ((udata_flags & PF_WRITE) && (vma_flags & VM_WRITE)) {
			physaddr_t* entry;
			struct page_info* old_page = page_lookup(task->task_pml4, base, &entry);

			assert(old_page != NULL);
			assert(entry != NULL);
			assert(old_page->pp_ref > 0);

			if (old_page->pp_ref == 1) {
				protect_region(task->task_pml4, base, size, (PAGE_UMASK & *entry) | PAGE_WRITE);
			} else {
				struct page_info* new_page = page_alloc_with_retry(0);
				assert_oom(new_page);

				*entry &= PAGE_MASK;
				*entry |= PAGE_ADDR(page2pa(new_page));
				*entry |= PAGE_WRITE;

				atomic_dec(&old_page->pp_ref);
				atomic_inc(&new_page->pp_ref);

				#ifdef USE_PAGE_SWAP
					assert(&new_page->pp_refs != NULL);
					struct pte_swap_page *swap_page = pte_swap_page_alloc(entry);
					assert(swap_page != NULL);
					spin_lock(&swap_page->entry_list_lock);
					list_add(&new_page->pp_refs, &swap_page->entry_node);
					spin_unlock(&swap_page->entry_list_lock);

					remove_from_ref_list(entry, old_page);
				#endif

				memcpy(page2kva(new_page), page2kva(old_page), PAGE_SIZE);
			}

			tlb_invalidate(task->task_pml4, base);

			return 0;
		} else {
			return -1;
		}
	}

	if(udata_flags & PF_WRITE) {
		// If attempting to write to a non-writable VMA, throw an error
		if(!(vma_flags & VM_WRITE)) {
			return -1;
		}
	} else {
		// If attempting to read from a non-readable VMA, throw an error
		if(!(vma_flags & VM_READ)) {
			return -1;
		}
	}

	// Internal error caused by writing to reserved bits. Always throw an error
	if(udata_flags & PF_RESERVED) {
		return -1;
	}

	// If attempting to execute a non-executable area, throw error
	if((udata_flags & PF_IFETCH) && !(vma_flags & VM_EXEC)) {
		return -1;
	}

	// As the page we want to map might not cover a whole VMA (and might even lay
	// right inside one), we calculate which address to map within this VMA
	// and how many bytes
	void* const map_start = MAX(base, vma->vm_base);
	const size_t map_size = MIN(base + size, vma->vm_end) - map_start;

	// Fill this region with pages
	populate_region(task->task_pml4, map_start, map_size, PAGE_WRITE, 1);

	if (vma->vm_src) {
		const size_t src_offset = map_start - vma->vm_base;
		const size_t src_cpy_limit = src_offset + MIN(vma->vm_len - src_offset, map_size);

		for(size_t curr_offset = src_offset; curr_offset < src_cpy_limit; curr_offset += PAGE_SIZE) {
			const size_t num_to_copy = MIN(PAGE_SIZE, src_cpy_limit - curr_offset);

			void* const curr_va = vma->vm_base + curr_offset;
			void* const src_kva = vma->vm_src + curr_offset;

			struct page_info* const page = page_lookup(task->task_pml4, curr_va, NULL);

			assert(page != NULL);

			memcpy(page2kva(page), src_kva, num_to_copy);
		}
	}

	uint64_t flags = PAGE_USER;

	if (!(vma_flags & VM_EXEC)) {
		flags |= PAGE_NO_EXEC;
	}

	if (vma_flags & VM_WRITE) {
		flags |= PAGE_WRITE;
	}

	protect_region(task->task_pml4, map_start, map_size, flags);

	return 0;
}

/* Populates the VMAs for the given address range [base, base + size) by
 * backing the VMAs with physical pages.
 */
int populate_vma_range(struct task *task, void *base, size_t size, int flags)
{
	assert(page_aligned((uintptr_t) base));
	assert(size % PAGE_SIZE == 0);

	return walk_vma_range(task, base, size, do_populate_vma, &flags);
}
