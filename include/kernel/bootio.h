#pragma once

#include <assert.h>

#define VMEM ((char*)0xb8000)

#define BOOTIO_BLACK (0)
#define BOOTIO_BLUE (1)
#define BOOTIO_GREEN (2)
#define BOOTIO_CYAN (3)
#define BOOTIO_RED (4)
#define BOOTIO_PURPLE (5)
#define BOOTIO_BROWN (6)
#define BOOTIO_GRAY (7)
#define BOOTIO_DARKGRAY (8)
#define BOOTIO_LIGHTBLUE (9)
#define BOOTIO_LIGHTGREEN (10)
#define BOOTIO_LIGHTCYAN (11)
#define BOOTIO_LIGHTRED (12)
#define BOOTIO_LIGHTPURPLE (13)
#define BOOTIO_YELLOW (14)
#define BOOTIO_WHITE (15)

#define BOOTIO_DEFAULT_FG (BOOTIO_GRAY)
#define BOOTIO_DEFAULT_BG (BOOTIO_BLACK)


#define bootio_compute_color(fg, bg) ((char) ((char)0xf & fg) | ((char)0x70 & (bg << 4)))

/**
 * Protected mode video color bytes are arranged as follows:
 * |SBBBFFFF|
 *
 * Where:
 *  S is a special bit which is dependent on the current BIOS mode
 *  B are the background color bits
 *  F are the foreground color bits
 */
char bootio_get_color_byte(const char fg, const char bg);

/**
 * Prints a single char to the display.
 *
 * Requires a formatted colorbyte
 */
void bootio_print_char(const char c, const char colorbyte);

/**
 * Prints the given string to the display.
 *
 * fg and bg colors need to be one of the colors defined in the macros
 * of this file
 */
void bootio_print_string(const char* s, const int fg, const int bg);

/**
 * Clears the current screen to all black
 */
void bootio_clear_screen(void);

/**
 * Outputs a single character to the display in the default colors
 */
void bootio_putc(const char c);

static inline size_t bootio_index_from_coords(int x, int y) {
    assert(x >= 0 && x <= 80);
    assert(y >= 0 && y <= 25);

    return ((80 * y) + x) * 2;
}
