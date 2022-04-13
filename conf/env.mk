# env.mk - configuration variables for the OpenLSD lab

# '$(V)' controls whether the lab makefiles print verbose commands (the
# actual shell commands run by Make), as well as the "overview" commands
# (such as '+ cc lib/readline.c').
#
# For overview commands only, the line should read 'V = @'.
# For overview and verbose commands, the line should read 'V ='.
V = @

# If your system-standard GNU toolchain is ELF-compatible, then comment
# out the following line to use those tools (as opposed to the i386-jos-elf
# tools that the 6.828 make system looks for by default).
#
# GCCPREFIX=''

# If the makefile cannot find your QEMU binary, uncomment the
# following line and set it to the full path to QEMU.
#
QEMU=qemu-system-x86_64
# QEMUEXTRA='-m 512M'
# CFLAGS +=-O0 -g3
# CFLAGS +=-v
# CFLAGS=-O3
# CFLAGS += -DBONUS_LAB1
# CFLAGS += -DBONUS_LAB2
# CFLAGS += -DBONUS_LAB3
# CFLAGS += -fpic -pie
# CFLAGS += -DLAB3_SYSCALL
CFLAGS += -DDEBUG_MODE
# CFLAGS += -DDEBUG_MAP_TABLES_MODE
# CFLAGS += -DDEBUG_WALKER_MODE
# CFLAGS += -DDEBUG_MAP_KERNEL_MODE
# CFLAGS += -DDEBUG_MAP_REGION_MODE
# CFLAGS += -DDEBUG_MAP_TABLES_ALLOC_MODE
# CFLAGS += -DDEBUG_INSERT_PAGE_MODE
# CFLAGS += -DDEBUG_LOOKUP_PAGE_MODE
# CFLAGS += -DDEBUG_REMOVE_PAGE_MODE
# CFLAGS += -DDEBUG_PTBL_OPS_MODE
# CFLAGS += -DDEBUG_PTBL_HUGE_MODE
# CFLAGS += -DDEBUG_PAGE_EXT_MODE
# CFLAGS += -DDEBUG_CPU_LOCKS_MODE
# CFLAGS += -DDEBUG_BOOT_CPUS_MODE
# CFLAGS += -DDEBUG_INT_HANDLER_MODE
# CFLAGS += -DDEBUG_SYSCALL_MODE
# CFLAGS += -DDEBUG_TASK_RUN_MODE
# CFLAGS += -DDEBUG_SCHED_MODE
# CFLAGS += -DDEBUG_HALT_MODE
# CFLAGS += -DDEBUG_TASK_FREE_MODE
CFLAGS += -DDEBUG_SPINLOCK
# CFLAGS += -DUSE_PAGE_SWAP
# CFLAGS += -DDO_SWAP_OUT
# CFLAGS += DDO_SWAP_IN
# CFLAGS += -DUSE_BIG_KERNEL_LOCK
# CFLAGS += -DUSE_KERNEL_THREADS
# QEMUEXTRA=-d int -no-reboot -no-shutdown
# QEMUEXTRA=-monitor stdio
