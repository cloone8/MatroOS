#include <types.h>

#include <kernel/bootio.h>
#include <kernel/mem.h>
#include <assert.h>

unsigned int bootio_index = 0;

char bootio_get_color_byte(const char fg, const char bg) {
    assert(fg >= 0 && fg < 16);
    assert(bg >= 0 && bg < 16);

    char colorbyte = 0;

    colorbyte |= (0xf & fg); // Lowest 4 bits is the foreground color
    colorbyte |= (0x70 & (bg << 4));

    return colorbyte;
}

void bootio_print_char(const char c, const char colorbyte) {
    *(VMEM + bootio_index) = c;
    *((VMEM + bootio_index) + 1) = colorbyte;

    bootio_index += 2;
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

    for(int i = 0; i < 25; i++) {
		for(int j = 0; j < 80; j++) {
			bootio_print_char(' ', colorbyte);
		}
	}

    bootio_index = 0;
}
