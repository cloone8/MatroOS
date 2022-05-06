#include <types.h>

#include <kernel/output.h>
#include <kernel/mem.h>
#include <assert.h>

static int cur_x = 0;
static int cur_y = 0;

char vga_textmode_get_color_byte(const char fg, const char bg) {
    assert(fg >= 0 && fg < 16);
    assert(bg >= 0 && bg < 16);

    return vga_textmode_compute_color(fg, bg);
}

static inline char* get_vmem_location(void) {
    if(long_mode_enabled) {
        return (char*) KADDR((physaddr_t) VMEM);
    } else {
        return VMEM;
    }
}

void vga_textmode_print_char(const char c, const char colorbyte) {
    const size_t cur_vmem_index = vga_textmode_index_from_coords(cur_x, cur_y);
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
        vga_textmode_clear_screen();
    }
}

void vga_textmode_putc(const char c) {
    vga_textmode_print_char(c, vga_textmode_compute_color(VGA_TEXTMODE_DEFAULT_FG, VGA_TEXTMODE_DEFAULT_BG));
}

void vga_textmode_print_string(const char* s, const int fg, const int bg) {
    assert(fg >= 0 && fg < 16);
    assert(bg >= 0 && bg < 16);

    const char colorbyte = vga_textmode_get_color_byte((const char) fg, (const char) bg);

    char* s_cur = (char*) s;

    while(1) {
        const char c = *s_cur++;

        if(c == 0) {
            return;
        }

        vga_textmode_print_char(c, colorbyte);
    }
}

void vga_textmode_clear_screen(void) {
    const char colorbyte = vga_textmode_get_color_byte(VGA_TEXTMODE_BLACK, VGA_TEXTMODE_BLACK);
    char* vmem_location = get_vmem_location();

    for(int i = 0; i < 25 * 80; i++) {
        const size_t cur_mem_index = i * 2;
        *(vmem_location + cur_mem_index) = ' ';
        *((vmem_location + cur_mem_index) + 1) = colorbyte;
	}

    cur_x = 0;
    cur_y = 0;
}
