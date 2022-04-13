#pragma once

void boot_cpus(void);

#ifndef USE_BIG_KERNEL_LOCK
void start_mp_task_handling(void);
#endif
