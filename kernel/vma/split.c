#include <task.h>
#include <vma.h>
#include <assert.h>
#include <kernel/vma.h>
#include <kernel/mem.h>

/* Given a task and a VMA, this function splits the VMA at the given address
 * by setting the end address of original VMA to the given address and by
 * adding a new VMA with the given address as base.
 */
struct vma *split_vma(struct task *task, struct vma *lhs, void *addr)
{
	assert(lhs->vm_base < addr && addr < lhs->vm_end);
	assert(!lhs->vm_src);

	// Create the new VMA. Do this manually, as add_vma and the add_*_vma functions
	// all merge the new VMA immediately
	struct vma* rhs = kmalloc(sizeof(struct vma));

	assert(rhs != NULL);

    list_init(&rhs->vm_mmap);
    rb_node_init(&rhs->vm_rb);

    rhs->vm_name = lhs->vm_name;
    rhs->vm_base = addr;
    rhs->vm_end = lhs->vm_end;
    rhs->vm_src = NULL;
    rhs->vm_len = 0;
    rhs->vm_flags = lhs->vm_flags;

	const int retval = insert_vma(task, rhs);

	assert(retval >= 0);

	lhs->vm_end = rhs->vm_base;

	return rhs;
}

/* Given a task and a VMA, this function first splits the VMA into a left-hand
 * and right-hand side at address base. Then this function splits the
 * right-hand side or the original VMA, if no split happened, into a left-hand
 * and a right-hand side. This function finally returns the right-hand side of
 * the first split or the original VMA.
 */
struct vma *split_vmas(struct task *task, struct vma *vma, void *base, size_t size)
{
	assert(task != NULL);
	assert(vma != NULL);

	struct vma* lhs = vma;
	struct vma* mid = vma;
	struct vma* rhs = vma;

	// Split the VMA into a left-hand side and a right-hand side
	if(base != vma->vm_base) {
		mid = split_vma(task, vma, base);
	}

	if(mid->vm_end != mid->vm_base + size) {
		rhs = split_vma(task, mid, mid->vm_base + size);
	}

	return mid;
}
