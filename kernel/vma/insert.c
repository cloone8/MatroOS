#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Inserts the given VMA into the red-black tree of the given task. First tries
 * to find a VMA for the end address of the given end address. If there is
 * already a VMA that overlaps, this function returns -1. Then the VMA is
 * inserted into the red-black tree and added to the sorted linked list of
 * VMAs.
 */
int insert_vma(struct task *task, struct vma *vma) {
	struct rb_node *node, *parent = NULL;
    struct vma *vma_tmp = NULL;
	int dir = 0;

	node = task->task_rb.root;

	while (node) {
		vma_tmp = container_of(node, struct vma, vm_rb);
		parent = node;
		dir = (vma->vm_base >= vma_tmp->vm_end);

		if (!dir) {
		    /* If dir == 0 check if we don't overlap vma_tmp */
            if (vma->vm_end > vma_tmp->vm_base){
                return -1;
            }
		}

		node = node->child[dir];
	}

    if (!parent){
        task->task_rb.root = &vma->vm_rb;
    } else {
        parent->child[dir] = &vma->vm_rb;
        vma->vm_rb.parent = parent;
    }

    /* Balance the RED-BLACK tree after VMA insertion */
	if (rb_insert(&task->task_rb, &vma->vm_rb) < 0) {
		return -1;
	}

	if (!parent) {
		list_insert_after(&task->task_mmap, &vma->vm_mmap);
	} else {
        assert(vma_tmp);
		if (dir) {
			list_insert_after(&vma_tmp->vm_mmap, &vma->vm_mmap);
		} else {
			list_insert_before(&vma_tmp->vm_mmap, &vma->vm_mmap);
		}
	}

	return 0;
}

/* Allocates and adds a new VMA for the given task.
 *
 * This function first allocates a new VMA. Then it copies over the given
 * information. The VMA is then inserted into the red-black tree and linked
 * list. Finally, this functions attempts to merge the VMA with the adjacent
 * VMAs.
 *
 * Returns the new VMA if it could be added, NULL otherwise.
 */
struct vma *add_executable_vma(struct task *task, char *name, void *addr,
                               size_t size, int flags, void *src, size_t len) {
    struct vma *prev, *vma;
    struct rb_node *parent = NULL, *node;
    void *end;
    int dir;

    if (!task || size == 0) {
        return NULL;
    }

    assert(!(src == NULL && len != 0));

    end = (void *)((uintptr_t)addr + size);

    // Round everything to page sizes
    void* addr_round = (void*) ROUNDDOWN((uintptr_t) addr, PAGE_SIZE);
    const size_t extra_len_before = addr - addr_round;

    size += extra_len_before;
    addr = addr_round;

    size = ROUNDUP(size, PAGE_SIZE);

    if(src != NULL) {
        assert((size_t) src > extra_len_before);

        src -= extra_len_before;
        len += extra_len_before;
    }

    end = (void *) ROUNDUP(((uintptr_t)addr + size), PAGE_SIZE);

    vma = kmalloc(sizeof *vma);

    if (!vma) {
        return NULL;
    }

    list_init(&vma->vm_mmap);
    rb_node_init(&vma->vm_rb);

    vma->vm_name = name;
    vma->vm_base = addr;
    vma->vm_end = end;
    vma->vm_src = src;
    vma->vm_len = len;
    vma->vm_flags = flags;

    if (insert_vma(task, vma) < 0) {
        kfree(vma);
        return NULL;
    }

    return merge_vmas(task, vma);
}

/* A simplified wrapper to add anonymous VMAs, i.e. VMAs not backed by an
 * executable.
 */
struct vma *add_anonymous_vma(struct task *task, char *name, void *addr,
                              size_t size, int flags) {
    return add_executable_vma(task, name, addr, size, flags, NULL, 0);
}

/* Allocates and adds a new VMA to the requested address or tries to find a
 * suitable free space that is sufficiently large to host the new VMA. If the
 * address is NULL, this function scans the address space from the end to the
 * beginning for such a space. If an address is given, this function scans the
 * address space from the given address to the beginning and then scans from
 * the end to the given address for such a space.
 *
 * Returns the VMA if it could be added. NULL otherwise.
 */
struct vma *add_vma(struct task *task, char *name, void *addr, size_t size,
                    int flags) {
    /* LAB 4: your code here. */
    struct vma *vma = NULL;
    struct list *node, *prev, *initial;
    void *base, *end;

    if (addr) {
        vma = find_vma(NULL, NULL, &task->task_rb, addr);
        node = vma ? &vma->vm_mmap : NULL;
    }

    if (!vma) {
        node = list_prev(&task->task_mmap, &task->task_mmap);
        vma = node ? container_of(node, struct vma, vm_mmap) : NULL;
    }

    if (!vma) {
        return add_anonymous_vma(task, name, (void *)(USER_LIM - size), size,
                                 flags);
    }

    initial = node;

    do {
        end = vma->vm_base;
        prev = list_prev(&task->task_mmap, node);

        if (!prev) {
            base = (void *)0x1000;
            node = list_prev(&task->task_mmap, &task->task_mmap);
        } else {
            vma = container_of(prev, struct vma, vm_mmap);
            base = vma->vm_end;
            node = prev;
        }

        if (size > (uintptr_t)end - (uintptr_t)base) {
            continue;
        }

        if (base <= addr && addr < end) {
            if (size <= (uintptr_t)end - (uintptr_t)addr) {
                return add_anonymous_vma(task, name, addr, size, flags);
            }
        }

        return add_anonymous_vma(task, name, (void *)((uintptr_t)end - size),
                                 size, flags);
    } while (node != initial);

    return NULL;
}

