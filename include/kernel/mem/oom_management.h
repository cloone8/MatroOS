#pragma once

#include <types.h>

#define assert_oom(x) if(!x) { panic("Kernel out of memory!"); }

size_t get_rss(struct task* task);
size_t oom(void);
struct page_info *page_alloc_with_retry(int alloc_flags);
