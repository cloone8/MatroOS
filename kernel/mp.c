#include <x86-64/asm.h>

#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/debug.h>

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock boot_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "boot_lock",
#endif
};
#endif


/* While boot_cpus() is booting a given CPU, it communicates the per-core stack
 * pointer that should be loaded by boot_ap().
 */
void *mpentry_kstack;

void boot_cpus(void)
{
	DEBUG_BOOT_CPUS("Booting CPUs\n");
	extern unsigned char boot_ap16[], boot_ap_end[];
	void *code;
	struct cpuinfo *cpu;

	/* Write entry code at the reserved page at MPENTRY_PADDR. */
	code = KADDR(MPENTRY_PADDR);
	memmove(code, KADDR((physaddr_t)boot_ap16), boot_ap_end - boot_ap16);

	#ifdef USE_BIG_KERNEL_LOCK
		DEBUG("Using BIG_KERNEL_LOCK\n");
		spin_lock(&kernel_lock);
	#endif

	#ifndef USE_BIG_KERNEL_LOCK
		DEBUG("Using fine-grained locking\n");
		spin_lock(&boot_lock);
	#endif

	/* Boot each CPU one at a time. */
	for (cpu = cpus; cpu < cpus + ncpus; ++cpu) {
		/* Skip the boot CPU */
		if (cpu == boot_cpu) {
			continue;
		}

		/* Set up the kernel stack. */
		mpentry_kstack = (void *)cpu->cpu_tss.rsp[0];

		DEBUG_BOOT_CPUS("Booting CPU %u\n", cpu->cpu_id);

		/* Start the CPU at boot_ap16(). */
		lapic_startup(cpu->cpu_id, PADDR(code));

		/* Wait until the CPU becomes ready. */
		while (cpu->cpu_status != CPU_STARTED);

		DEBUG_BOOT_CPUS("CPU %u status set to started, continuing\n", cpu->cpu_id);
	}

	DEBUG_BOOT_CPUS("All CPUs booted\n");

	#ifdef USE_BIG_KERNEL_LOCK
		spin_unlock(&kernel_lock);
	#endif
}

#ifndef USE_BIG_KERNEL_LOCK
void start_mp_task_handling(void) {

	DEBUG_BOOT_CPUS("Letting CPUs start handling tasks\n");

	spin_unlock(&boot_lock);
}
#endif

void mp_main(void)
{
	/* Eable the NX-bit. */
	write_msr(MSR_EFER, read_msr(MSR_EFER) | MSR_EFER_NXE);

	/* Load the kernel PML4. */
	asm volatile("movq %0, %%cr3\n" :: "r" (PADDR(kernel_pml4)));

	/* Load the per-CPU kernel stack. */
	asm volatile("movq %0, %%rsp\n" :: "r" (mpentry_kstack));

	cprintf("SMP: CPU %d starting with stack %p\n", lapic_cpunum(), mpentry_kstack);

	// Initialize the local APIC
	lapic_init();

	/* Set up segmentation, interrupts, system call support. */
	gdt_init_mp();
	idt_init_mp();
	kmem_init();
	syscall_init_mp();

	// Initialise the local runqueues
	sched_init_mp();

	/* Notify the main CPU that we started up. */
	DEBUG_BOOT_CPUS("CPU %u done booting\n", this_cpu->cpu_id);
	xchg(&this_cpu->cpu_status, CPU_STARTED);

	/* Schedule tasks. */
	#ifdef USE_BIG_KERNEL_LOCK
		spin_lock(&kernel_lock);
		sched_start();
	#else
	// Just to make sure we don't continue running until the boot CPU has started
	// all CPUs and they're all ready
		spin_lock(&boot_lock);
		spin_unlock(&boot_lock);

		sched_start();
	#endif
}
