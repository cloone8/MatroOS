#include <types.h>

#include <kernel/bootio.h>
#include <kernel/mem.h>
#include <assert.h>

static int cur_x = 0;
static int cur_y = 0;

char bootio_get_color_byte(const char fg, const char bg) {
    assert(fg >= 0 && fg < 16);
    assert(bg >= 0 && bg < 16);

    return bootio_compute_color(fg, bg);
}

static inline char* get_vmem_location(void) {
    if(long_mode_enabled) {
        return (char*) KADDR((physaddr_t) VMEM);
    } else {
        return VMEM;
    }
}

void bootio_print_char(const char c, const char colorbyte) {
    const size_t cur_vmem_index = bootio_index_from_coords(cur_x, cur_y);
    char* vmem_location = get_vmem_location();

    switch(c) {
        case '\n':
            cur_y += 1;
            cur_x = 0;
            break;
        case '\r':
            cur_x = 0;
            break;
        default:
            *(vmem_location + cur_vmem_index) = c;
            *((vmem_location + cur_vmem_index) + 1) = colorbyte;
            cur_x += 1;
            break;
    }

    // Next character would be wrapping off the screen
    if(cur_x == 80) {
        cur_x = 0;
        cur_y += 1;
    }

    if(cur_y == 25) {
        // TODO: Implement scrolling
        bootio_clear_screen();
    }
}

void bootio_putc(const char c) {
    bootio_print_char(c, bootio_compute_color(BOOTIO_DEFAULT_FG, BOOTIO_DEFAULT_BG));
}

void bootio_print_string(const char* s, const int fg, const int bg) {
    assert(fg >= 0 && fg < 16);
    assert(bg >= 0 && bg < 16);

    const char colorbyte = bootio_get_color_byte((const char) fg, (const char) bg);

    char* s_cur = (char*) s;

    while(1) {
        const char c = *s_cur++;

        if(c == 0) {
            return;
        }

        bootio_print_char(c, colorbyte);
    }
}

void bootio_clear_screen(void) {
    const char colorbyte = bootio_get_color_byte(BOOTIO_BLACK, BOOTIO_BLACK);
    char* vmem_location = get_vmem_location();

    for(int i = 0; i < 25 * 80; i++) {
        const size_t cur_mem_index = i * 2;
        *(vmem_location + cur_mem_index) = ' ';
        *((vmem_location + cur_mem_index) + 1) = colorbyte;
	}

    cur_x = 0;
    cur_y = 0;
}
