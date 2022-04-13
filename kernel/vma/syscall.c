#include <types.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

#include <lib.h>

int sys_mquery(struct vma_info *info, void *addr)
{
	struct vma *vma;
	struct list *node;
	physaddr_t *entry;

	/* Check if the user has read/write access to the info struct. */
	assert_user_mem(cur_task, info, sizeof *info, PAGE_USER | PAGE_WRITE);

	/* Do not leak information about the kernel space. */
	if (addr >= (void *)USER_LIM) {
		return -1;
	}

	/* Clear the info struct. */
	memset(info, 0, sizeof *info);

	/* Find the VMA with an end address that is greater than the requested
	 * address, but also the closest to the requested address.
	 */
	vma = find_vma(NULL, NULL, &cur_task->task_rb, addr);

	if (!vma) {
		/* If there is no such VMA, it means the address is greater
		 * than the address of any VMA in the address space, i.e. the
		 * user is requesting the free gap at the end of the address
		 * space. The base address of this free gap is the end address
		 * of the highest VMA and the end address is simply USER_LIM.
		 */
		node = list_tail(&cur_task->task_mmap);

		info->vm_end = (void *)USER_LIM;

		if (!node) {
			return 0;
		}

		vma = container_of(node, struct vma, vm_mmap);
		info->vm_base = vma->vm_end;

		return 0;
	}

	if (addr < vma->vm_base) {
		/* The address lies outside the found VMA. This means the user
		 * is requesting the free gap between two VMAs. The base
		 * address of the free gap is the end address of the previous
		 * VMA. The end address of the free gap is the base address of
		 * the VMA that we found.
		 */
		node = list_prev(&cur_task->task_mmap, &vma->vm_mmap);

		info->vm_end = vma->vm_base;

		if (!node) {
			return 0;
		}

		vma = container_of(node, struct vma, vm_mmap);
		info->vm_base = vma->vm_end;

		return 0;
	}

	/* The requested address actually lies within a VMA. Copy the
	 * information.
	 */
	strncpy(info->vm_name, vma->vm_name, 64);
	info->vm_base = vma->vm_base;
	info->vm_end = vma->vm_end;
	info->vm_prot = vma->vm_flags;
	info->vm_type = vma->vm_src ? VMA_EXECUTABLE : VMA_ANONYMOUS;

	/* Check if the address is backed by a physical page. */
	if (page_lookup(cur_task->task_pml4, addr, &entry)) {
		info->vm_mapped = (*entry & PAGE_HUGE) ? VM_2M_PAGE : VM_4K_PAGE;
	}

	return 0;
}

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd,
	uintptr_t offset)
{
	int vma_flags = 0;

	if (prot & PROT_READ) {
		vma_flags |= VM_READ;
	}

	if (prot & PROT_WRITE) {
		vma_flags |= VM_WRITE;
	}

	if (prot & PROT_EXEC) {
		vma_flags |= VM_EXEC;
	}

	if (len <= 0) {
		return MAP_FAILED;
	}

	// For now, fd is not set.
	if (fd != -1) {
		panic("aaaaah");
		return MAP_FAILED;
	}

	// Outside of kernel.
	if ((uint64_t) addr >= USER_LIM) {
		return MAP_FAILED;
	}

	// PROT_NONE
	if (prot == 0) {
		struct vma* new_vma = add_vma(cur_task, "user", addr, len, PROT_NONE);

		if(new_vma == NULL) {
			return MAP_FAILED;
		}

		return new_vma->vm_base;
	}

	if ((prot & PROT_WRITE) || (prot & PROT_EXEC)) {
		if ((prot & PROT_READ) == 0) {
			return MAP_FAILED;
		}
	}

	if (flags & MAP_FIXED) {
		if(!page_aligned((uintptr_t) addr)) {
			return MAP_FAILED;
		}

		struct vma* old = task_find_vma(cur_task, addr);

		if (old) {
			struct vma* split_old = split_vmas(cur_task, old, addr, len);
			if(remove_vma_range(cur_task, split_old->vm_base, split_old->vm_end - split_old->vm_base) < 0) {
				return MAP_FAILED;
			}
		}

		struct vma* new_vma = add_vma(cur_task, "user", addr, len, vma_flags);

		if(new_vma == NULL) {
			return MAP_FAILED;
		}

		if(addr != new_vma->vm_base) {
			return MAP_FAILED;
		}

		return new_vma->vm_base;
	}

	if (flags & MAP_POPULATE) {
		if (flags & MAP_PRIVATE) {
			if(populate_vma_range(cur_task, addr, len, 0) < 0) {
				return MAP_FAILED;
			}
		} else {
			// Not supported.
			return MAP_FAILED;
		}
	}

	struct vma* new_vma = add_vma(cur_task, "user", addr, len, vma_flags);

	if(new_vma == NULL) {
		return MAP_FAILED;
	} else {
		return new_vma->vm_base;
	}
}

void sys_munmap(void *addr, size_t len)
{
	if ((uint64_t)addr >= USER_LIM) {
		return;
	}

    struct vma *old = task_find_vma(cur_task, addr);
	if (strcmp(old->vm_name, "user") != 0) {
		cprintf("[PID %5u] user fault va %p ip %p\n", cur_task->task_pid, addr, cur_task->task_frame.rip);
		print_int_frame(&cur_task->task_frame);
		task_kill(cur_task);
		return;
	}
    remove_vma_range(cur_task, addr, len);
}

int sys_mprotect(void *addr, size_t len, int prot)
{
	int vma_flags = 0;

	if ((uint64_t) addr >= USER_LIM) {
		return -1;
	}

	if ((prot & PROT_WRITE) && !(prot & PROT_READ)) {
		return -1;
	}

	if ((prot & PROT_EXEC) && !(prot & PROT_READ)) {
		return -1;
	}

    if (prot & PROT_READ) {
        vma_flags |= VM_READ;
    }

    if (prot & PROT_WRITE) {
        vma_flags |= VM_WRITE;
    }

    if (prot & PROT_EXEC) {
        vma_flags |= VM_EXEC;
    }

    struct vma *old = task_find_vma(cur_task, addr);
	void* const map_start = MAX(addr, old->vm_base);
	const size_t map_size = MIN(addr + len, old->vm_end) - map_start;

	if (old) {
		protect_vma_range(cur_task, addr, len, vma_flags);
	}

	if (prot == 0) {
		protect_vma_range(cur_task, addr, len, PROT_NONE);
	}

    return 0;
}

int sys_madvise(void *addr, size_t len, int advise)
{
    if ((uint64_t)addr >= USER_LIM) {
        return -1;
    }

	struct vma *vma = task_find_vma(cur_task, addr);
	int prot = 0;

	switch (advise) {
	case MADV_DONTNEED:
		unmap_vma_range(cur_task, addr, len);
		break;
	case MADV_WILLNEED:
		if (vma->vm_flags & VM_READ) {
			prot |= PROT_READ;
		}

		if (vma->vm_flags & VM_WRITE) {
			prot |= PROT_WRITE;
		}

		if (vma->vm_flags & VM_EXEC) {
			prot |= PROT_EXEC;
		}
		if (vma->vm_flags == 0) {
			prot = PROT_NONE;
		}
		populate_vma_range(cur_task, addr, len, vma->vm_flags);
		break;
	default:
		break;
	}
	return 0;
}
