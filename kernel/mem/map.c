#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <elf.h>
#include <stdio.h>

#define RESERVED_MASK ((uintptr_t)(~(PAGE_UMASK | ~PAGE_MASK)))

struct boot_map_info {
	struct page_table *pml4;
	uint64_t flags;
	physaddr_t pa;
	uintptr_t base, end;
};

/* Stores the physical address and the appropriate permissions into the PTE and
 * increments the physical address to point to the next page.
 */
static int boot_map_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	DEBUG_MAP_TABLES("Mapping PTE %p\n", entry);

	struct boot_map_info *info = walker->udata;

	const uintptr_t phys_address = info->pa;
	info->pa += PAGE_SIZE;

	const physaddr_t flags = info->flags | PAGE_PRESENT;

	(*entry) = flags;
	(*entry) |= PAGE_ADDR(phys_address);

	assert(PAGE_ADDR(*entry) == PAGE_ADDR(phys_address));

	// Sanity check
	const physaddr_t recovered_addr = PAGE_ADDR((*entry));

	DEBUG_MAP_TABLES("Done mapping PTE %p\n", entry);
	return 0;
}

/*
 * Maps the virtual address space at [va, va + size) to the contiguous physical
 * address space at [pa, pa + size). Size is a multiple of PAGE_SIZE. The
 * permissions of the page to set are passed through the flags argument.
 *
 * This function is only intended to set up static mappings. As such, it should
 * not change the reference counts of the mapped pages.
 *
 * Hint: this function calls walk_page_range().
 */
void boot_map_region(struct page_table *pml4, void *va, size_t size,
    physaddr_t pa, uint64_t flags)
{
	DEBUG_MAP_REGION("Mapping boot region\n\t%p -> %p\n\tphysaddr: %p -> %p\n\tflags: 0x%x\n", va, (uintptr_t) va + size, pa, pa + size, flags);

	/* LAB 2: your code here. */
	struct boot_map_info info = {
		.pa = pa,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
		.pml4 = pml4
	};

	struct page_walker walker = {
		.pte_callback = boot_map_pte,
		.pde_callback = ptbl_alloc,
		.pdpte_callback = ptbl_alloc,
		.pml4e_callback = ptbl_alloc,
		.udata = &info,
	};

	const int retval = walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);

	assert(retval >= 0);

	DEBUG_MAP_REGION("Done mapping boot region\n");
}

/* Creates a mapping in the MMIO region to [pa, pa + size) for
 * memory-mapped I/O.
 */
void *mmio_map_region(physaddr_t pa, size_t size)
{
	static uintptr_t base = MMIO_BASE;
	void *ret;

	size = ROUNDUP(size, PAGE_SIZE);
	assert(base + size < MMIO_LIM);

	ret = (void *)base;

	DEBUG_MAP_REGION("Mapping MMIO region\n\t%p -> %p\n\tphysaddr: %p -> %p\n\tflags: 0x%x\n", base, (uintptr_t) base + size, pa, pa + size, PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC | PAGE_WRITE_THROUGH | PAGE_NO_CACHE);

	boot_map_region(kernel_pml4, ret, size, pa, PAGE_PRESENT |
		PAGE_WRITE | PAGE_NO_EXEC | PAGE_WRITE_THROUGH | PAGE_NO_CACHE);
	base += size;

	return ret;
}

/* This function parses the program headers of the ELF header of the kernel
 * to map the regions into the page table with the appropriate permissions.
 *
 * First creates an identity mapping at the KERNEL_VMA of size BOOT_MAP_LIM
 * with permissions RW-.
 *
 * Then iterates the program headers to map the regions with the appropriate
 * permissions.
 *
 * Hint: this function calls boot_map_region().
 * Hint: this function ignores program headers below KERNEL_VMA (e.g. ".boot").
 */
void boot_map_kernel(struct page_table *pml4, struct elf *elf_hdr)
{
	DEBUG_MAP_KERNEL("Mapping kernel\n");

	struct elf_proghdr *prog_hdrs =
	    (struct elf_proghdr *)((char *)elf_hdr + elf_hdr->e_phoff);

	boot_map_region(pml4, (void*) KERNEL_VMA, BOOT_MAP_LIM, 0, PAGE_WRITE | PAGE_NO_EXEC);

	for (size_t i = 0; i < elf_hdr->e_phnum; i++) {
		DEBUG_MAP_KERNEL("Mapping prog_hdr %u\n", i);
		struct elf_proghdr* prog_hdr = prog_hdrs + i;

		if(prog_hdr->p_va < KERNEL_VMA) {
			DEBUG_MAP_KERNEL("Header below kernelspace, skipping\n");
			continue;
		}

		uint64_t flags = 0;
		const uint32_t proghdr_flags = prog_hdr->p_flags;

		DEBUG_MAP_KERNEL("ELF flags: 0x%llx\n", proghdr_flags);

		if(proghdr_flags & ELF_PROG_FLAG_WRITE) {
			DEBUG_MAP_KERNEL("Setting PAGE_WRITE flag\n");
			flags |= PAGE_WRITE;
		}

		if(!(proghdr_flags & ELF_PROG_FLAG_EXEC)) {
			DEBUG_MAP_KERNEL("Setting PAGE_NO_EXEC flag\n");
			flags |= PAGE_NO_EXEC;
		}

		boot_map_region(pml4, (void*)prog_hdr->p_va, prog_hdr->p_memsz, prog_hdr->p_pa, flags);
	}
}

