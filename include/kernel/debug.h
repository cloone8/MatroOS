#pragma once

#include <stdio.h>

#ifdef DEBUG_MODE
    #define DEBUG(...) (cprintf_dbg("", __VA_ARGS__))

    #ifdef DEBUG_MAP_TABLES_MODE
        #define DEBUG_MAP_TABLES(...) (cprintf_dbg("[BOOT_MAP_TABLES] ", __VA_ARGS__))
    #else
        #define DEBUG_MAP_TABLES(...)
    #endif

    #ifdef DEBUG_MAP_TABLES_ALLOC_MODE
        #define DEBUG_MAP_TABLES_ALLOC(...) (cprintf_dbg("[MAP_TABLES_ALLOC] ", __VA_ARGS__))
    #else
        #define DEBUG_MAP_TABLES_ALLOC(...)
    #endif

    #ifdef DEBUG_MAP_REGION_MODE
        #define DEBUG_MAP_REGION(...) (cprintf_dbg("[BOOT_MAP_REGION] ", __VA_ARGS__))
    #else
        #define DEBUG_MAP_REGION(...)
    #endif

    #ifdef DEBUG_MAP_KERNEL_MODE
        #define DEBUG_MAP_KERNEL(...) (cprintf_dbg("[BOOT_MAP_KERNEL] ", __VA_ARGS__))
    #else
        #define DEBUG_MAP_KERNEL(...)
    #endif

    #ifdef DEBUG_WALKER_MODE
        #define DEBUG_WALKER(...) (cprintf_dbg("[WALKER] ", __VA_ARGS__))
    #else
        #define DEBUG_WALKER(...)
    #endif

    #ifdef DEBUG_INSERT_PAGE_MODE
        #define DEBUG_INSERT_PAGE(...) (cprintf_dbg("[INSERT_PAGE] ", __VA_ARGS__))
    #else
        #define DEBUG_INSERT_PAGE(...)
    #endif

    #ifdef DEBUG_LOOKUP_PAGE_MODE
        #define DEBUG_LOOKUP_PAGE(...) (cprintf_dbg("[LOOKUP_PAGE] ", __VA_ARGS__))
    #else
        #define DEBUG_LOOKUP_PAGE(...)
    #endif

    #ifdef DEBUG_REMOVE_PAGE_MODE
        #define DEBUG_REMOVE_PAGE(...) (cprintf_dbg("[REMOVE_PAGE] ", __VA_ARGS__))
    #else
        #define DEBUG_REMOVE_PAGE(...)
    #endif

    #ifdef DEBUG_PTBL_OPS_MODE
        #define DEBUG_PTBL_OPS(...) (cprintf_dbg("[PTBL_OPS] ", __VA_ARGS__))
    #else
        #define DEBUG_PTBL_OPS(...)
    #endif

    #ifdef DEBUG_PTBL_HUGE_MODE
        #define DEBUG_PTBL_HUGE(...) (cprintf_dbg("[PTBL_HUGE] ", __VA_ARGS__))
    #else
        #define DEBUG_PTBL_HUGE(...)
    #endif

    #ifdef DEBUG_PAGE_EXT_MODE
        #define DEBUG_PAGE_EXT(...) (cprintf_dbg("[PAGE_EXT]", __VA_ARGS__))
    #else
        #define DEBUG_PAGE_EXT(...)
    #endif

    #ifdef DEBUG_CPU_LOCKS_MODE
        #define DEBUG_CPU_LOCKS(x) (x)
    #else
        #define DEBUG_CPU_LOCKS(x)
    #endif

    #ifdef DEBUG_BOOT_CPUS_MODE
        #define DEBUG_BOOT_CPUS(...) (cprintf_dbg("[BOOT_CPUS] ", __VA_ARGS__))
    #else
        #define DEBUG_BOOT_CPUS(...)
    #endif

    #ifdef DEBUG_INT_HANDLER_MODE
        #define DEBUG_INT_HANDLER(...) (cprintf_dbg("[INT_HANDLER] ", __VA_ARGS__))
    #else
        #define DEBUG_INT_HANDLER(...)
    #endif

    #ifdef DEBUG_SYSCALL_MODE
        #define DEBUG_SYSCALL(...) (cprintf_dbg("[SYSCALL] ", __VA_ARGS__))
    #else
        #define DEBUG_SYSCALL(...)
    #endif

    #ifdef DEBUG_TASK_RUN_MODE
        #define DEBUG_TASK_RUN(...) (cprintf_dbg("[TASK_RUN] ", __VA_ARGS__))
    #else
        #define DEBUG_TASK_RUN(...)
    #endif

    #ifdef DEBUG_SCHED_MODE
        #define DEBUG_SCHED(...) (cprintf_dbg("[SCHED] ", __VA_ARGS__))
    #else
        #define DEBUG_SCHED(...)
    #endif

    #ifdef DEBUG_HALT_MODE
        #define DEBUG_HALT(...) (cprintf_dbg("[HALT] ", __VA_ARGS__))
    #else
        #define DEBUG_HALT(...)
    #endif

    #ifdef DEBUG_TASK_FREE_MODE
        #define DEBUG_TASK_FREE(...) (cprintf_dbg("[TASK_FREE] ", __VA_ARGS__))
    #else
        #define DEBUG_TASK_FREE(...)
    #endif
#else
    #define DEBUG(...)
    #define DEBUG_WALKER(...)
    #define DEBUG_MAP_KERNEL(...)
    #define DEBUG_MAP_REGION(...)
    #define DEBUG_MAP_TABLES_ALLOC(...)
    #define DEBUG_MAP_TABLES(...)
    #define DEBUG_INSERT_PAGE(...)
    #define DEBUG_LOOKUP_PAGE(...)
    #define DEBUG_REMOVE_PAGE(...)
    #define DEBUG_PTBL_OPS(...)
    #define DEBUG_PTBL_HUGE(...)
    #define DEBUG_PAGE_EXT(...)
    #define DEBUG_CPU_LOCKS(x)
    #define DEBUG_BOOT_CPUS(...)
    #define DEBUG_INT_HANDLER(...)
    #define DEBUG_SYSCALL(...)
    #define DEBUG_TASK_RUN(...)
    #define DEBUG_SCHED(...)
    #define DEBUG_HALT(...)
    #define DEBUG_TASK_FREE(...)
#endif
