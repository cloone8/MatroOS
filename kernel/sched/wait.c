#include <types.h>
#include <cpu.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	return sys_waitpid(-1, rstatus, 0);
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	struct list* node;
	struct task* found_zombie = NULL;

	if(pid == cur_task->task_pid) {
		return -ECHILD;
	}

	if(list_is_empty(&cur_task->task_children) && list_is_empty(&cur_task->task_zombies)) {
		return -ECHILD;
	}

	list_foreach(&cur_task->task_zombies, node) {
		struct task* zombie_task = container_of(node, struct task, task_node);

		if(pid == -1 || zombie_task->task_pid == pid) {
			found_zombie = zombie_task;
			break;
		}
	}

	if (found_zombie != NULL) {
		#ifndef USE_BIG_KERNEL_LOCK
			spin_lock(&found_zombie->task_lock);
		#endif

		const pid_t id = found_zombie->task_pid;

		list_del(&found_zombie->task_node);
		task_final_free(found_zombie);

		return id;
	} else {
		if(pid != -1) {
			struct task* to_wait_on = pid2task(pid, 1);

			if(to_wait_on == NULL) {
				return -ECHILD;
			}

			cur_task->task_wait = to_wait_on;
		}

		cur_task->task_status = TASK_NOT_RUNNABLE;

		#ifndef USE_BIG_KERNEL_LOCK
			spin_unlock(&cur_task->task_lock);
		#endif
		sched_start(); // Current task not runnable anymore, try anotherone
		panic("Should have yielded");
	}
}
