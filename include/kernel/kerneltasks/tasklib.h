#pragma once

#include <types.h>
#include <kernel/mem.h>
#include <cpu.h>

void kernel_task_remove_stack(struct task* kernel_task);
void* kernel_task_alloc_stack(struct page_table* task_pml4);
void kernel_task_main(int (*task_main)(void));
extern void __kernel_task_end(struct cpuinfo* cur_cpu);
extern void __kernel_task_yield(struct cpuinfo* cur_cpu);
extern void __kernel_task_start(struct int_frame* frame);

#define kernel_task_end() __kernel_task_end(this_cpu)
#define kernel_task_yield() __kernel_task_yield(this_cpu)
#define kernel_task_start(x) __kernel_task_start(x)
