#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/console.h>
#include <kernel/dev/pci.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/debug.h>
#include <kernel/mp.h>
#include <kernel/pic.h>
#include <kernel/sched.h>
#include <kernel/tests.h>
#include <kernel/kerneltasks.h>
#include <kernel/bootio.h>

#include <boot.h>
#include <stdio.h>
#include <string.h>

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif


// Sanity checks for development
void check_const_integrity(void) {
	assert(sizeof(struct int_frame) == INT_FRAME_SIZE);
}

void kmain(struct boot_info *boot_info)
{
	extern char edata[], end[];
	struct rsdp *rsdp;
	int retval;

	/* Before doing anything else, complete the ELF loading process.
	 * Clear the uninitialized global data (BSS) section of our program.
	 * This ensures that all static/global variables start out zero.
	 */
	memset(edata, 0, end - edata);


	// Say hi
	bootio_clear_screen();
	bootio_print_string("Booting MatroOS\n", BOOTIO_GRAY, BOOTIO_BLACK);

	/* Initialize the console.
	 * Can't call cprintf until after we do this! */
	cons_init();

	#ifdef USE_PAGE_SWAP
		list_init(&clock_list);
	#endif

	check_const_integrity();

	/* Set up segmentation, interrupts and system calls. */
	gdt_init();
	idt_init();
	syscall_init();

	/* Lab 1 memory management initialization functions */
	cprintf("NOTE: The display output driver currently only supports 32 bit protected mode.\nOnce the kernel PML4 is loaded the switch to 64 bit long mode is made,\nwhich disables text output.\n\n");
	mem_init(boot_info);

	/* Set up the slab allocator. */
	kmem_init();

	/* Set up the interrupt controller and timers */
	pic_init();
	rsdp = rsdp_find();
	madt_init(rsdp);
	lapic_init();

	/* Initiate the kmalloc locks */
	retval = kmem_init_mp();
	assert(retval == 0);

	hpet_init(rsdp);
	pci_init(rsdp);

	/* Set up the tasks. */
	task_init();

	sched_init();
	sched_init_mp();

	mem_init_mp();

	// #ifdef USE_KERNEL_THREADS
		#ifdef USE_PAGE_SWAP
			struct task* t = kernel_task_create(&kswapd);
		#endif
		// kernel_task_create(&test_timer_interrupt);
		// kernel_task_create(&test_pfault);
	// #endif

	boot_cpus();

#if defined(TEST)

	#ifdef USE_BIG_KERNEL_LOCK
		spin_lock(&kernel_lock);
	#endif

	TASK_CREATE(TEST, TASK_TYPE_USER);

	#ifndef USE_BIG_KERNEL_LOCK
		start_mp_task_handling();
	#endif

	sched_start();
	panic("Should have started");
#else
	lab3_check_kmem();

        /* Drop into the kernel monitor. */
	while (1)
		monitor(NULL);
#endif
}

/*
 * Variable panicstr contains argument to first call to panic; used as flag
 * to indicate that the kernel has already called panic.
 */
const char *panicstr;

/*
 * Panic is called on unresolvable fatal errors.
 * It prints "panic: mesg", and then enters the kernel monitor.
 */
void _panic(const char *file, int line, const char *fmt,...)
{
	va_list ap;

	if (panicstr)
		goto dead;
	panicstr = fmt;

	/* Be extra sure that the machine is in as reasonable state */
	__asm __volatile("cli; cld");

	va_start(ap, fmt);
	cprintf("kernel panic in CPU %u at %s:%d: ", this_cpu->cpu_id, file, line);
	vcprintf(fmt, ap);
	cprintf("\n");
	va_end(ap);

dead:
	/* Break into the kernel monitor */
	while (1)
		monitor(NULL);
}

/* Like panic, but don't. */
void _warn(const char *file, int line, const char *fmt,...)
{
	va_list ap;

	va_start(ap, fmt);
	cprintf("kernel warning at %s:%d: ", file, line);
	vcprintf(fmt, ap);
	cprintf("\n");
	va_end(ap);
}
