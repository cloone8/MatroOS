#include <types.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock* kmem_locks;
#endif

/* Sets up slab allocators for every multiple of SLAB_ALIGN bytes starting from
 * SLAB_ALIGN.
 */
int kmem_init(void)
{
	struct slab *slab;
	size_t obj_size;
	size_t i;
	nslabs = 32;

	for (i = 0; i < nslabs; ++i) {
		slab = slabs + i;
		obj_size = (i + 1) * SLAB_ALIGN;
		slab_setup(slab, obj_size);
	}

	return 0;
}

int kmem_init_mp(void)
{
	#ifndef USE_BIG_KERNEL_LOCK
		assert(this_cpu == boot_cpu);

		struct spinlock temp_spinlock = {
			#ifdef DEBUG_SPINLOCK
			.name = "temp_spinlock"
			#endif
		};
		kmem_locks = &temp_spinlock;

		struct spinlock* spinlocks = kmalloc(ncpus * sizeof(struct spinlock));

		if(spinlocks == NULL) {
			return 1;
		}

		#ifdef DEBUG_SPINLOCK
			for(size_t i = 0; i < ncpus; i++) {
				spinlocks[i].name = kmalloc(32);
				snprintf((char*) spinlocks[i].name, 31, "kmem_lock_%lu", i);
			}
		#endif

		kmem_locks = spinlocks;
	#endif


	return 0;
}

/* Allocates a chunk of memory of size bytes.
 *
 * If the size is zero, this function returns NULL.
 * If the size is greater than or equal to the highest object size available in
 * the set of slab allocators, this function returns NULL.
 * Otherwise this function finds the best fit slab allocator for the requested
 * size and uses slab_alloc() to allocate the chunk of memory. */
void *kmalloc(size_t size)
{
	size_t index;
	if (size == 0) {
		return NULL;
	}

	size = ROUNDUP(size, SLAB_ALIGN);
	index = (size / SLAB_ALIGN) - 1;
	if (index >= nslabs) {
		return NULL;
	}

	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(kmem_locks + this_cpu->cpu_id);
	#endif

	void* retval = slab_alloc(slabs + index);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(kmem_locks + this_cpu->cpu_id);
	#endif

	return retval;
}

/* This function calls slab_free() to free the chunk of memory. */
void kfree(void *p)
{
	#ifndef USE_BIG_KERNEL_LOCK
		spin_lock(kmem_locks + this_cpu->cpu_id);
	#endif

	slab_free(p);

	#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(kmem_locks + this_cpu->cpu_id);
	#endif
}
