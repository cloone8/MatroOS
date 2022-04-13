#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/debug.h>

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif

struct list global_runq;

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock global_runq_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "global_runq_lock",
#endif
};
#endif

static inline void stop_this_core(void) {
	asm volatile(
		"cli\n"
		"hlt\n"
	);
}

/* Check if all the cpus are in the halting state. */
int all_cpus_halted(void) {
    for (struct cpuinfo* cpu = cpus; cpu < cpus + ncpus; ++cpu) {
		if (cpu->cpu_status != CPU_HALTED) {
			return 0;
		}
    }
	return 1;
}

void print_runq(struct list* runq) {
	assert(runq != NULL);

	if(runq != &global_runq) {
		cprintf("Printing local runq %p:\n", runq);
	} else {
		#ifndef USE_BIG_KERNEL_LOCK
			spin_lock(&global_runq_lock);
		#endif
		cprintf("Printing global runq:\n");
	}

	struct list* node;
	list_foreach(runq, node) {
		struct task* task = container_of(node, struct task, task_node);
		cprintf("    [PID %d]: PRIO: %lu TYPE: %lu\n", task->task_pid, task->task_time_use, task->task_type);
	}

	#ifndef USE_BIG_KERNEL_LOCK
	if(runq == &global_runq) {
		spin_unlock(&global_runq_lock);
	}
	#endif

	cprintf("\n");
}

int contains_runnable_tasks(struct list* runq) {
	assert(runq != NULL);

	struct list* node;
	list_foreach(runq, node) {
		struct task* task = container_of(node, struct task, task_node);

		if(task->task_status == TASK_RUNNABLE) {
			return 1;
		}
	}

	return 0;
}

void sched_init(void)
{
	list_init(&global_runq);
}

void sched_update_budget(struct task* task) {
	assert(task != NULL);
	assert(task->task_status != TASK_DYING);
	assert(task->killed != 1);

	uint64_t cur_tsc = read_tsc();

	task->task_time_use += cur_tsc - task->task_time;
	task->task_time = cur_tsc;
}

/* Find the task with the task with the lowest prio penalty */
struct task* get_highest_prio_task(struct list* runq) {
	assert(runq != NULL);

	#ifdef USE_BIG_KERNEL_LOCK
		assert(!list_is_empty(runq));
	#endif

	struct list* node;
	struct task* to_return = NULL;

	list_foreach_rev(runq, node) {
		struct task* task = container_of(node, struct task, task_node);

		if(task->task_status == TASK_RUNNABLE) {
			if(to_return == NULL || task->task_time_use < to_return->task_time_use) {
				to_return = task;
			}
		}
	}

	#ifdef USE_BIG_KERNEL_LOCK
		assert(to_return != NULL);
	#endif

	return to_return;
}

void sched_init_mp(void) {
	#ifndef USE_BIG_KERNEL_LOCK
	list_init(&this_cpu->runq);
	list_init(&this_cpu->nextq);
	this_cpu->runq_len = 0;
	#endif
}

#ifdef USE_BIG_KERNEL_LOCK
void sched_start(void) {
	if(contains_runnable_tasks(&global_runq)) {
		sched_yield();
	} else {
		sched_halt();
	}

	panic("Should have yielded or halted!");
}

/* Runs the next runnable task. */
void sched_yield(void) {
	#ifdef DEBUG_SPINLOCK
		assert(kernel_lock.locked && kernel_lock.cpu == this_cpu);
	#endif

	struct task* to_run = get_highest_prio_task(&global_runq);
	list_del(&to_run->task_node);
	task_run(to_run);
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	// Set the current CPU to halted
	this_cpu->cpu_status = CPU_HALTED;
	xchg(&this_cpu->cpu_status, CPU_HALTED);

	// If all CPUs are halted, stop
	while(1) {
		assert(this_cpu->cpu_status == CPU_HALTED);
		spin_unlock(&kernel_lock);

		if(all_cpus_halted()) {
			if(this_cpu == boot_cpu) {
				cprintf("Destroyed the only task - nothing more to do!\n");
				monitor(NULL);
			} else {
				// We can't actually stop the CPU yet, so just busy loop
				while(1);
			}
		} else {
			spin_lock(&kernel_lock);
			if(contains_runnable_tasks(&global_runq)) {
				// Set the current CPU to started
				this_cpu->cpu_status = CPU_STARTED;
				xchg(&this_cpu->cpu_status, CPU_STARTED);

				sched_yield();
				panic("Should have yielded or started!");
			}
		}

	}
}
#else // !USE_BIG_KERNEL_LOCK
void sched_start(void) {
	DEBUG_SCHED("Starting scheduler in CPU %u\n", this_cpu->cpu_id);
	if(contains_runnable_tasks(&this_cpu->runq)) {
		DEBUG_SCHED("Local runq in CPU %u contains runnable tasks\n", this_cpu->cpu_id);
		sched_yield();
	} else {
		DEBUG_SCHED("Local runq in CPU %u contains no runnable tasks\n", this_cpu->cpu_id);
		sched_halt();
	}

	panic("Should have yielded or halted!");
}

void sched_yield(void) {
	DEBUG_SCHED("CPU %u yielding new task\n", this_cpu->cpu_id);
	struct task* to_run = get_highest_prio_task(&this_cpu->runq);
	assert(to_run != NULL);
	spin_lock(&to_run->task_lock);
	list_del(&to_run->task_node);

	DEBUG_SCHED("CPU %u yielded task %lu\n", this_cpu->cpu_id, to_run->task_pid);
	task_run(to_run);
}

static void swap_runq_nextq(void) {
	DEBUG_SCHED("CPU %u swapping queues\n", this_cpu->cpu_id);

	struct list temp_q = LIST_INIT(temp_q);

	// First, remove all the nodes from the runq and add them to a temporary queue
	struct list* node;
	struct list* next;

	list_foreach_safe(&this_cpu->runq, node, next) {
		list_del(node);
		list_add(&temp_q, node);
	}

	assert(list_is_empty(&this_cpu->runq));

	// Now, migrate the nextq to the runq
	this_cpu->runq_len = 0;
	list_foreach_safe(&this_cpu->nextq, node, next) {
		list_del(node);
		list_add(&this_cpu->runq, node);
		this_cpu->runq_len++;
	}

	assert(list_is_empty(&this_cpu->nextq));

	// Finally move the tempq to the nextq, finishing the migration
	list_foreach_safe(&temp_q, node, next) {
		list_del(node);
		list_add(&this_cpu->nextq, node);
	}

	assert(list_is_empty(&temp_q));
}

/**
 * Starts the CPU and yields the next task
 * Does not return
 */
static void start_and_yield(void) {
	DEBUG_SCHED("CPU %u doing start-and-yield\n", this_cpu->cpu_id);

	#ifdef DEBUG_HALT_MODE
		if(this_cpu->cpu_status != CPU_STARTED) {
			DEBUG_HALT("CPU %u restarting\n", this_cpu->cpu_id);
		}
	#endif

	this_cpu->cpu_status = CPU_STARTED;
	xchg(&this_cpu->cpu_status, CPU_STARTED);

	sched_yield();
	panic("Should have yielded");
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	DEBUG_SCHED("CPU %u in halt check function\n", this_cpu->cpu_id);
	assert(this_cpu->cpu_status == CPU_STARTED);

	// If all CPUs are halted, stop
	while(1) {

		if(contains_runnable_tasks(&this_cpu->runq)) {
			// If the current runq contains runnable tasks,
			// mark the CPU as started and run a task from that queue
			start_and_yield();
		} else {
			if(spin_trylock(&global_runq_lock)) {
				// If the current runq does not contain runnable tasks, try to
				// get some from the global runq

				struct list* node;
				struct list* next;
				size_t num_taken = 0;

				list_foreach_safe(&global_runq, node, next) {
					list_del(node);
					list_add(&this_cpu->runq, node);
					this_cpu->runq_len++;
					num_taken++;

					if(num_taken >= MAX_TAKEN_FROM_GLOBAL_QUEUE) {
						break;
					}
				}

				spin_unlock(&global_runq_lock);

				if(!contains_runnable_tasks(&this_cpu->runq)) {
					// If we still don't have any runnable tasks even after migrating
					// from the global runq, just swap the two local runq's
					swap_runq_nextq();
				}
			} else {
				// If we can't get a lock on the global runq, just swap the nextq
				// and the current runq
				swap_runq_nextq();
			}

			// If we have runnable tasks in the local runq, run one
			if(contains_runnable_tasks(&this_cpu->runq)) {
				start_and_yield();
			} else {
				if(this_cpu->cpu_status != CPU_HALTED) {
					DEBUG_HALT("CPU %u starting temporary halt\n", this_cpu->cpu_id);

					// Set the current CPU to halted
					this_cpu->cpu_status = CPU_HALTED;
					xchg(&this_cpu->cpu_status, CPU_HALTED);
				}

				// If there are no runnable tasks anywhere, check if all CPUs are halted
				if(nuser_tasks == 0) {
					DEBUG_HALT("CPU %u permanently halting\n", this_cpu->cpu_id);

					if(this_cpu == boot_cpu) {

						cprintf("Destroyed the only task - nothing more to do!\n");
						monitor(NULL);
					} else {
						// We can't actually stop the CPU yet, so just busy loop
						stop_this_core();
					}

					panic("Shouldn't get here");
				}
			}

			// Finally, if there are no runnable tasks but not all CPUs are halted
			// either, just repeat the loop
			assert(this_cpu->cpu_status == CPU_HALTED);
		}
	}
}
#endif// USE_BIG_KERNEL_LOCK
