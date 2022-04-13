#pragma once

#include <kernel/sched.h>

#ifndef USE_BIG_KERNEL_LOCK
    #define MAX_TAKEN_FROM_GLOBAL_QUEUE (4)
#endif

int is_queued(struct task* task);
void print_runq(struct list* runq);
int contains_runnable_tasks(struct list* runq);
void sched_update_budget(struct task* task);
struct task* get_highest_prio_task(struct list* runq);
void sched_init(void);
void sched_init_mp(void);
void sched_start(void);
void sched_yield(void);
void sched_halt(void);
