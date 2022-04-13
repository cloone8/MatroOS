#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Changes the protection flags of the given VMA. Does nothing if the flags
 * would remain the same. Splits up the VMA into the address range
 * [base, base + size) and changes the protection of the physical pages backing
 * the VMA. Then attempts to merge the VMAs in case the protection became the
 * same as that of any of the adjacent VMAs.
 */
int do_protect_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
    int vma_flags = vma->vm_flags;
    int udata_flags = *(int *)(udata);
    int page_flags = PAGE_USER | PAGE_PRESENT;

    if (vma_flags == udata_flags) {
        return 0;
    }

    if (udata_flags & VM_WRITE) {
        page_flags |= PAGE_WRITE;
    }

    if (!(udata_flags & VM_EXEC)) {
        page_flags |= PAGE_NO_EXEC;
    }

    vma = split_vmas(task, vma, base, size);
    vma->vm_flags = udata_flags;

    void *const map_start = MAX(base, vma->vm_base);
    const size_t map_size = MIN(base + size, vma->vm_end) - map_start;

    // PROT_NONE
    if (!udata_flags) {
        protect_region(task->task_pml4, map_start, map_size, vma_flags);
        return 0;
    }

    protect_region(task->task_pml4, map_start, map_size, page_flags);

    merge_vmas(task, vma);

    return 0;
}

/* Changes the protection flags of the VMAs for the given address range
 * [base, base + size).
 */
int protect_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_protect_vma, &flags);
}

