#include <kernel/kerneltasks/tasklib.h>
#include <kernel/kerneltasks/tasks.h>

#define SWAP_MAX 255
// #define SWAP_MAX (128mb/ PAGE_SIZE)

#define N_SECTORS (PAGE_SIZE / SECT_SIZE)
#define swp_type(entry) ((entry >> 32) &0xff)
#define swp_offset(entry) ((entry >> 40))

struct page_reclaim {
    struct page_info* page;
    struct list pr_node;
    struct page_table* pml4;
    uintptr_t base_addr;
};

struct pte_swap_page {
    physaddr_t* entry;
    struct list entry_node;
    struct spinlock entry_list_lock;
};

struct swap_list {
    struct list swap_infos;
    size_t size;
};

struct swap_info {
    uint64_t offset_in_pages;
    uint64_t id;
    struct list ptes;
    struct list node;
};

struct swap_back_info {
    struct list node;
    size_t id;
    struct task* requesting_task;
    uintptr_t base_addr;
};
