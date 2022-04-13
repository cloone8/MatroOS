#include <types.h>
#include <boot.h>
#include <list.h>
#include <paging.h>
#include <stdio.h>

#include <x86-64/asm.h>

#include <kernel/mem.h>
#include <kernel/tests.h>
#include <kernel/debug.h>
#include <cpu.h>

extern struct list buddy_free_list[];

/* The kernel's initial PML4. */
struct page_table *kernel_pml4;

/* This function sets up the initial PML4 for the kernel. */
int pml4_setup(struct boot_info *boot_info)
{
	DEBUG("Starting kernel PML4 setup\n");
	struct page_info *page;

	/* Allocate the kernel PML4. */
	page = page_alloc(ALLOC_ZERO);

	assert_oom(page);

	kernel_pml4 = page2kva(page);

	/* Map in the regions used by the kernel from the ELF header passed to
	 * us through the boot info struct.
	 */
	DEBUG("Starting kernel boot map\n");
	boot_map_kernel(kernel_pml4, boot_info->elf_hdr);

	/* Use the physical memory that 'bootstack' refers to as the kernel
	 * stack. The kernel stack grows down from virtual address KSTACK_TOP.
	 * Map 'bootstack' to [KSTACK_TOP - KSTACK_SIZE, KSTACK_TOP).
	 */

	DEBUG("Starting bootstack map\n");
	boot_map_region(kernel_pml4, (void*) (KSTACK_TOP - KSTACK_SIZE), KSTACK_SIZE, (physaddr_t) bootstack, PAGE_WRITE | PAGE_NO_EXEC);

	/* Map in the pages from the buddy allocator as RW-. */

	DEBUG("Starting buddy page map\n");
	boot_map_region(kernel_pml4, (void*) KPAGES, npages * sizeof(struct page_info), (physaddr_t) PADDR(pages), PAGE_WRITE | PAGE_NO_EXEC);

	/* Migrate the struct page_info structs to the newly mapped area using
	 * buddy_migrate().
	 */

	DEBUG("Starting buddy migrate\n");
	buddy_migrate();

	DEBUG("PML4 setup done\n");
	return 0;
}

/*
 * Set up a four-level page table:
 * kernel_pml4 is its linear (virtual) address of the root
 *
 * This function only sets up the kernel part of the address space (i.e.
 * addresses >= USER_TOP). The user part of the address space will be set up
 * later.
 *
 * From USER_TOP to USER_LIM, the user is allowed to read but not write.
 * Above USER_LIM, the user cannot read or write.
 */
void mem_init(struct boot_info *boot_info) {
	DEBUG("Starting memory initialisation\n");
	struct mmap_entry *entry;
	uintptr_t highest_addr = 0;
	uint32_t cr0;
	size_t i, n;

	/* Align the areas in the memory map. */
	align_boot_info(boot_info);

	/* Set up the page free lists. */
	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		list_init(buddy_free_list + i);
	};

	/* Find the amount of pages to allocate structs for. */
	entry = (struct mmap_entry *)((physaddr_t)boot_info->mmap_addr);

	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		if (entry->type != MMAP_FREE) continue;

		highest_addr = entry->addr + entry->len;
	}

	/* Limit the struct page_info array to the first 8 MiB, as the rest is
	 * still not accessible until lab 2.
	 */
	npages = MIN(BOOT_MAP_LIM, highest_addr) / PAGE_SIZE;

	/* Remove this line when you're ready to test this function. */
	// panic("mem_init: This function is not finished\n");

	/*
	 * Allocate an array of npages 'struct page_info's and store it in 'pages'.
	 * The kernel uses this array to keep track of physical pages: for each
	 * physical page, there is a corresponding struct page_info in this array.
	 * 'npages' is the number of physical pages in memory.  Your code goes here.
	 */
	pages = boot_alloc(npages * sizeof *pages);

	/*
	 * Now that we've allocated the initial kernel data structures, we set
	 * up the list of free physical pages. Once we've done so, all further
	 * memory management will go through the page_* functions. In particular, we
	 * can now map memory using boot_map_region or page_insert.
	 */
	page_init(boot_info);

	// /* We will set up page tables here in lab 2. */

	/* Setup the initial PML4 for the kernel. */
	DEBUG("Loading kernel PML4\n");
	pml4_setup(boot_info);

	/* Enable the NX-bit. */
	DEBUG("Writing MSR NXE\n");
	write_msr(MSR_EFER, read_msr(MSR_EFER) | MSR_EFER_NXE);

	/* Check the kernel PML4. */
	lab2_check_pml4();

	/* Load the kernel PML4. */
	DEBUG("Writing PML4 (va: %p, pa: %p) to CR3\n", kernel_pml4, PADDR(kernel_pml4));
	load_pml4((struct page_table*) PADDR(kernel_pml4));
	DEBUG("Done loading kernel PML4\n");

	/* Check the paging functions. */
	lab2_check_paging();

	/* Add the rest of the physical memory to the buddy allocator. */
	DEBUG("Mapping remaining RAM\n");
	page_init_ext(boot_info);
	DEBUG("Done mapping RAM\n");

	/* Check the buddy allocator. */
	lab2_check_buddy(boot_info);
}

/**
 * What address is reserved?
 *  - Address 0 contains the IVT and BIOS data.
 *  - boot_info->elf_hdr points to the ELF header.
 *  - Any address in [KERNEL_LMA, end) is part of the kernel.
 */
static inline int is_reserved(physaddr_t addr, struct mmap_entry* entry, struct boot_info* boot_info, uintptr_t end) {
	int reserved = 0;

	reserved |= addr == 0;
	reserved |= addr == PAGE_ADDR(PADDR(boot_info));
	reserved |= addr == (physaddr_t) boot_info->elf_hdr;
	reserved |= ((addr >= KERNEL_LMA) && (addr < end));

	return reserved;
}

void mem_init_mp(void) {
	/* Set up kernel stacks for each CPU here. Make sure they have a guard
	 * page.
	 */
	const size_t kstack_total_size = KSTACK_SIZE + KSTACK_GAP;
	cprintf("%p->%p\n", KSTACK_TOP - (ncpus * kstack_total_size), KSTACK_TOP);

	for (size_t i = 0; i < ncpus; i++) {
		struct cpuinfo* cpu = cpus + i;

		const uintptr_t stack_top = KSTACK_TOP - (i * kstack_total_size);

		for (uintptr_t cur_page = stack_top - kstack_total_size; cur_page < stack_top; cur_page += PAGE_SIZE) {
			struct page_info* stack_page = page_alloc_with_retry(ALLOC_ZERO);
			assert_oom(stack_page);

			boot_map_region(kernel_pml4, (void*) cur_page, PAGE_SIZE, page2pa(stack_page), PAGE_WRITE | PAGE_NO_EXEC);
		}

		cpu->cpu_tss.rsp[0] = stack_top;
	}
}

/*
 * Initialize page structure and memory free list. After this is done, NEVER
 * use boot_alloc() again. After this function has been called to set up the
 * memory allocator, ONLY the buddy allocator should be used to allocate and
 * free physical memory.
 */
void page_init(struct boot_info *boot_info)
{
	struct page_info *page;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	// Go through the array of struct page_info structs
	for (i = 0; i < npages; ++i) {
		struct page_info* current_page = pages + i;

		// Call list_init() to initialize the linked list node
		list_init(&current_page->pp_node);

		// Set the reference count pp_ref to zero
		current_page->pp_ref = 0;

		// Mark the page as in use by setting pp_free to zero
		current_page->pp_free = 0;

		// Set the order pp_order to zero
		current_page->pp_order = 0;
	}

	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	end = PADDR(boot_alloc(0));

	// Go through the entries in the memory map
	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {

		// Ignore the entry if the region is not free memory
		if (entry->type != MMAP_FREE) {
			continue;
		}

		// Iterate through the pages in the region
		for (physaddr_t phys_addr = entry->addr; phys_addr < (entry->addr + entry->len); phys_addr += PAGE_SIZE) {

			// If the physical address is above BOOT_MAP_LIM, ignore
			if (phys_addr >= BOOT_MAP_LIM) {
				continue;
			}

			// Hand the page to the buddy allocator by calling page_free() if the page is not reserved
			if(!is_reserved(phys_addr, entry, boot_info, end)) {
				page = pa2page(phys_addr);
				page_free(page);
			}
		}
	}
}

/* Extend the buddy allocator by initializing the page structure and memory
 * free list for the remaining available memory.
 */
void page_init_ext(struct boot_info *boot_info)
{
	struct page_info *page;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	end = PADDR(boot_alloc(0));

	DEBUG_PAGE_EXT("Starting with %lluKiB\n", npages * 4);
	DEBUG_PAGE_EXT("Examining %llu boot info entries\n", boot_info->mmap_len);

	/* Go through the entries in the memory map:
	 *  1) Ignore the entry if the region is not free memory.
	 *  2) Iterate through the pages in the region.
	 *  3) If the physical address is below BOOT_MAP_LIM, ignore.
	 *  4) Hand the page to the buddy allocator by calling page_free().
	 */
	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		DEBUG_PAGE_EXT("Examining boot info entry %u\n", i);

		if (entry->type != MMAP_FREE && i != 4) { // DIRTY HACK ALERT
			DEBUG_PAGE_EXT("Entry not free memory\n");
			continue;
		}


		// Determine the actual address to start mapping
		physaddr_t start_addr = entry->addr;
		uint64_t region_size = entry->len;

		while(start_addr < BOOT_MAP_LIM && start_addr < (entry->addr + entry->len)) {
			start_addr += PAGE_SIZE;
			region_size -= PAGE_SIZE;
		}

		// Iterate through the pages in the region
		for (physaddr_t phys_addr = start_addr; phys_addr < (start_addr + region_size); phys_addr += PAGE_SIZE) {
			// See if we need to allocate more pages for buddy metadata
			while(PAGE_INDEX(phys_addr) >= npages) {
				DEBUG_PAGE_EXT("Mapping more buddy chunks\n");
				const int retval = buddy_map_chunk(kernel_pml4, PAGE_INDEX(phys_addr));

				if(retval != 0) {
					panic("Kernel out of memory!");
				}

				DEBUG_PAGE_EXT("Done mapping more buddy chunks\n");
			}

			// Uphold the 1:1 mapping
			boot_map_region(kernel_pml4, (void*) KADDR(phys_addr), PAGE_SIZE, phys_addr, PAGE_WRITE | PAGE_NO_EXEC);

			// Map the page by calling page_free()
			if(i != 4) { // DIRTY HACK ALERT
				page = pa2page(phys_addr);
				page_free(page);
			}
		}

		#if defined(DEBUG_MODE) && defined(DEBUG_PAGE_EXT_MODE)
			size_t mem_num = npages * 4;
			char* mem_str = "KiB";

			if(mem_num > 1024) {
				mem_num /= 1024;
				mem_str = "MiB";
			}

			if(mem_num > 1024) {
				mem_num /= 1024;
				mem_str = "GiB";
			}
			cprintf_dbg("[PAGE_EXT] ", "Memory increased to %llu%s\n", mem_num, mem_str);
		#endif
	}
}
