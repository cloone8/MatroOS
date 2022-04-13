#include <task.h>
#include <vma.h>

#include <kernel/vma.h>
#include <stdio.h>

/* Given a task and two VMAs, checks if the VMAs are adjacent and compatible
 * for merging. If they are, then the VMAs are merged by removing the
 * right-hand side and extending the left-hand side by setting the end address
 * of the left-hand side to the end address of the right-hand side.
 */
struct vma *merge_vma(struct task *task, struct vma *lhs, struct vma *rhs)
{
	if (lhs->vm_flags != rhs->vm_flags) {
		return NULL;
	}

	// End of lhs is same as base of rhs.
	if (lhs->vm_end != rhs->vm_base) {
		return NULL;
	}

	// Source files not compatible
	if(lhs->vm_src || rhs->vm_src) {

		// Both areas need to have a source file
		if(!(lhs->vm_src && rhs->vm_src)) {
			return NULL;
		}

		// The mapped areas from the source file need to be adjacent
		if(lhs->vm_src + lhs->vm_len != rhs->vm_src) {
			return NULL;
		}
	}

	// Extend the memory area
	lhs->vm_end = rhs->vm_end;

	// Extend the source file mapping
	lhs->vm_len += rhs->vm_len;

	// Free the rhs VMA
	remove_vma(task, rhs);

	return lhs;
}

/* Given a task and a VMA, this function attempts to merge the given VMA with
 * the previous and the next VMA. Returns the merged VMA or the original VMA if
 * the VMAs could not be merged.
 */
struct vma *merge_vmas(struct task *task, struct vma *vma)
{
	struct list* prev_list = list_prev(&task->task_mmap, &vma->vm_mmap);

	if(prev_list) {
		struct vma* prev = container_of(prev_list, struct vma, vm_mmap);
		struct vma* lhs_merge_result = merge_vma(task, prev, vma);

		// If the merge was done, the new lhs is now
		// the merge result
		if(lhs_merge_result != NULL) {
			vma = lhs_merge_result;
		}
	}

	struct list* next_list = list_next(&task->task_mmap, &vma->vm_mmap);

	if(next_list) {
		struct vma* next = container_of(vma->vm_mmap.next, struct vma, vm_mmap);
		// Result does not matter, as either the lhs is extended or it isn't. In any
		// case we only need to return the lhs, which is vma in this case
		merge_vma(task, vma, next);
	}

	return vma;
}
