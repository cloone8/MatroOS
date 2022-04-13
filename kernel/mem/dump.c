#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#include <kernel/debug.h>
#include <stdio.h>

struct dump_info {
	uintptr_t base;
	uintptr_t end;
	uint64_t flags;
	uint64_t mask;
};

struct dump_entries_info {
	uint16_t pml4e_index;
	uint16_t pdpte_index;
	uint16_t pde_index;
	uint16_t pte_index;
};

/* Print the region before the hole if there was any and reset the info struct.
 */
static int dump_hole(uintptr_t base, uintptr_t end, struct page_walker *walker)
{
	struct dump_info *info = walker->udata;

	if (info->flags & PAGE_PRESENT) {
		cprintf("  %016p - %016p [%c%c%c%c",
			info->base,
			info->end,
			(info->flags & PAGE_PRESENT) ? 'r' : '-',
			(info->flags & PAGE_WRITE) ? 'w' : '-',
			(info->flags & PAGE_NO_EXEC) ? '-' : 'x',
			(info->flags & PAGE_USER) ? 'u' : '-'
		);

		if (info->mask & PAGE_HUGE) {
			cprintf(" %s",
				(info->flags & PAGE_HUGE) ? "2M" : "4K"
			);
		}

		cprintf("]\n");
	}

	info->flags = 0;

	return 0;
}

/* Update the end pointer if the flags are the same. Otherwise print the region
 * and keep track of the new region.
 */
static int dump_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct dump_info *info = walker->udata;
	uint64_t flags;

	flags = *entry & info->mask;

	if (flags == info->flags) {
		info->end = end;

		return 0;
	}

	dump_hole(base, end, walker);

	info->base = base;
	info->end = end;
	info->flags = flags;

	return 0;
}

/* Update the end pointer if the flags are the same and the PDE points to a
 * huge page. Otherwise print the region and keep track of the new region.
 */
static int dump_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct dump_info *info = walker->udata;
	uint64_t flags;

	if (!(*entry & PAGE_HUGE))
		return 0;

	flags = *entry & info->mask;

	if (flags == info->flags) {
		info->end = end;

		return 0;
	}

	dump_hole(base, end, walker);

	info->base = base;
	info->end = end;
	info->flags = flags;

	return 0;
}

/* Given the root pml4 to the page table hierarchy, dumps the mapped regions
 * with the same flags. mask can be PAGE_HUGE to differentiate regions mapped
 * with normal pages from those mapped with huge pages.
 */
int dump_page_tables(struct page_table *pml4, uint64_t mask)
{
	DEBUG("Dumping all page tables\n");
	struct dump_info info = {
		.base = 0,
		.flags = 0,
		.mask = mask | PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC |
		        PAGE_USER,
	};
	struct page_walker walker = {
		.pte_callback = dump_pte,
		.pde_callback = dump_pde,
		.pt_hole_callback = dump_hole,
		.udata = &info,
	};

	if (walk_all_pages(pml4, &walker) < 0)
		return -1;

	dump_hole(0, 0, &walker);

	DEBUG("Done dumping page tables\n");
	return 0;
}

static inline void get_flags_str(char* flag_str, uint64_t flags) {
	flag_str[0] = flags & PAGE_USER ? 'u' : '-';
	flag_str[1] = flags & PAGE_WRITE ? 'w' : '-';
	flag_str[2] = flags & PAGE_NO_EXEC ? '-' : 'x';
	flag_str[3] = '\0';

	return;
}

static int dump_pml4e_content(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker)
{
	struct dump_entries_info *info = walker->udata;

	const int indents = 1;
	const unsigned int entry_index = info->pml4e_index++;
	const physaddr_t entry_content = *entry;

	info->pdpte_index = 0;

	if(!(entry_content & PAGE_PRESENT)) {
		return 0;
	}

	for(int i = 0; i < indents * 4; i++) {
		cputchar(' ');
	}

	char flag_str[4];

	get_flags_str(flag_str, entry_content & PAGE_UMASK);

	cprintf("%u: PML4e (va: %p, pa: %p) (flags: [%s]): %p -> %p\n", entry_index, entry, PADDR(entry), flag_str, base, end);

	return 0;
}

static int dump_pdpte_content(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker)
{
	struct dump_entries_info *info = walker->udata;

	const int indents = 2;
	const unsigned int entry_index = info->pdpte_index++;
	const physaddr_t entry_content = *entry;

	info->pde_index = 0;

	if(!(entry_content & PAGE_PRESENT)) {
		return 0;
	}

	for(int i = 0; i < indents * 4; i++) {
		cputchar(' ');
	}

	char flag_str[4];

	get_flags_str(flag_str, entry_content & PAGE_UMASK);

	cprintf("%u: PDPTe (va: %p, pa: %p) (flags: [%s]): %p -> %p\n", entry_index, entry, PADDR(entry), flag_str, base, end);

	return 0;
}

static int dump_pde_content(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker)
{
	struct dump_entries_info *info = walker->udata;

	const int indents = 3;
	const unsigned int entry_index = info->pde_index++;
	const physaddr_t entry_content = *entry;

	info->pte_index = 0;

	if(!(entry_content & PAGE_PRESENT)) {
		return 0;
	}

	for(int i = 0; i < indents * 4; i++) {
		cputchar(' ');
	}

	char flag_str[4];

	get_flags_str(flag_str, entry_content & PAGE_UMASK);

	cprintf("%u: PDe (va: %p, pa: %p) (flags: [%s]): %p -> %p\n", entry_index, entry, PADDR(entry), flag_str, base, end);

	return 0;
}

static int dump_pte_content(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker)
{
	struct dump_entries_info *info = walker->udata;

	const int indents = 4;
	const unsigned int entry_index = info->pte_index++;
	const physaddr_t entry_content = *entry;

	if(!(entry_content & PAGE_PRESENT)) {
		return 0;
	}

	for(int i = 0; i < indents * 4; i++) {
		cputchar(' ');
	}

	char flag_str[4];

	get_flags_str(flag_str, entry_content & PAGE_UMASK);

	cprintf("%u: PTe (va: %p, pa: %p) (flags: [%s]): %p -> %p ===> %p -> %p\n", entry_index, entry, PADDR(entry), flag_str, base, end, PAGE_ADDR(entry_content), PAGE_ADDR(entry_content) + PAGE_SIZE);

	return 0;
}

int dump_table_entries(struct page_table *pml4)
{
	DEBUG("Dumping page table entries\n");

	struct dump_entries_info info = {
		.pml4e_index = 0,
		.pdpte_index = 0,
		.pde_index = 0,
		.pte_index = 0
	};

	struct page_walker walker = {
		.pml4e_callback = dump_pml4e_content,
		.pdpte_callback = dump_pdpte_content,
		.pde_callback = dump_pde_content,
		.pte_callback = dump_pte_content,
		.udata = &info
	};

	cprintf("\nPML4: %p (at %p):\n", pml4, PADDR(pml4));

	const int retval = walk_all_pages(pml4, &walker);

	assert(retval >= 0);

	cputchar('\n');

	DEBUG("Done dumping page table entries\n");

	return retval;
}
