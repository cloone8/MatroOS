#pragma once

struct cpuinfo;

struct spinlock {
	/* Is the lock held? */
	volatile unsigned locked;

#ifdef DEBUG_SPINLOCK
	/* The name of the lock. */
	const char *name;

	/* The CPU that is holding the lock. */
	struct cpuinfo *cpu;

	/* The filename and line at which the last successful lock took
	 * place.
	 */
	const char *file;
	int line;
#endif
};

#ifndef DEBUG_CPU_LOCKS_MODE
	#define spin_lock(lock) __spin_lock(lock, __FILE__, __LINE__)
	#define spin_trylock(lock) __spin_trylock(lock, __FILE__, __LINE__)
	#define spin_unlock(lock) __spin_unlock(lock, __FILE__, __LINE__)
#else
	#define spin_lock(lock) __spin_lock(lock, __FILE__, __LINE__, 1)
	#define spin_trylock(lock) __spin_trylock(lock, __FILE__, __LINE__, 1)
	#define spin_unlock(lock) __spin_unlock(lock, __FILE__, __LINE__, 1)
#endif

void spin_init(struct spinlock *lock, const char *name);

#ifndef DEBUG_CPU_LOCKS_MODE
	void __spin_lock(struct spinlock *lock, const char *file, int line);
	void __spin_unlock(struct spinlock *lock, const char *file, int line);
	int __spin_trylock(struct spinlock *lock, const char *file, int line);
#else
	void __spin_lock(struct spinlock *lock, const char *file, int line, int with_debug_prints);
	void __spin_unlock(struct spinlock *lock, const char *file, int line, int with_debug_prints);
	int __spin_trylock(struct spinlock *lock, const char *file, int line, int with_debug_prints);
#endif
