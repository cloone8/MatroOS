#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Removes the given VMA from the given task. */
void remove_vma(struct task *task, struct vma *vma)
{
	if (!task || !vma) {
		return;
	}

	rb_remove(&task->task_rb, &vma->vm_rb);

	rb_node_init(&vma->vm_rb);

	list_del(&vma->vm_mmap);

	kfree(vma);
}

/* Frees all the VMAs for the given task. */
void free_vmas(struct task *task)
{
	struct list* node;
	struct list* next;

	list_foreach_safe(&task->task_mmap, node, next) {
		struct vma* vma = container_of(node, struct vma, vm_mmap);
		remove_vma(task, vma);
	}
}

/* Splits the VMA into the address range [base, base + size) and removes the
 * resulting VMA and any physical pages that back the VMA.
 */
int do_remove_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	void* const to_remove_base = MAX(base, vma->vm_base);
	void* const to_remove_end = MIN(base + size, vma->vm_end);
	const size_t to_remove_size = to_remove_end - to_remove_base;

	struct vma* to_remove;

	if(to_remove_base == vma->vm_base && to_remove_end == vma->vm_end) {
		to_remove = vma;
	} else {
		to_remove = split_vmas(task, vma, to_remove_base, to_remove_size);
	}

	unmap_page_range(task->task_pml4, to_remove_base, to_remove_size);

	remove_vma(task, to_remove);

	return 0;
}

/* Removes the VMAs and any physical pages backing those VMAs for the given
 * address range [base, base + size).
 */
int remove_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_remove_vma, NULL);
}

/* Removes any non-dirty physical pages for the given address range
 * [base, base + size) within the VMA.
 */
int do_unmap_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
    void *const to_remove_base = MAX(base, vma->vm_base);
    void *const to_remove_end = MIN(base + size, vma->vm_end);
    const size_t to_remove_size = to_remove_end - to_remove_base;

    unmap_page_range(task->task_pml4, to_remove_base, to_remove_size);
    return 0;
}

/* Removes any non-dirty physical pages within the address range
 * [base, base + size).
 */
int unmap_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_unmap_vma, NULL);
}
