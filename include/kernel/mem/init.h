#pragma once

#include <boot.h>
#include <assert.h>
#include <paging.h>

#include <x86-64/memory.h>

extern struct page_table *kernel_pml4;
extern int long_mode_enabled;

void mem_init_mp(void);
void mem_init(struct boot_info *boot_info);
void page_init(struct boot_info *boot_info);
void page_init_ext(struct boot_info *boot_info);
