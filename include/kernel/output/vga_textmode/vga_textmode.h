#pragma once

#include <assert.h>

#define VMEM ((char*)0xb8000)

#define VGA_TEXTMODE_BLACK (0)
#define VGA_TEXTMODE_BLUE (1)
#define VGA_TEXTMODE_GREEN (2)
#define VGA_TEXTMODE_CYAN (3)
#define VGA_TEXTMODE_RED (4)
#define VGA_TEXTMODE_PURPLE (5)
#define VGA_TEXTMODE_BROWN (6)
#define VGA_TEXTMODE_GRAY (7)
#define VGA_TEXTMODE_DARKGRAY (8)
#define VGA_TEXTMODE_LIGHTBLUE (9)
#define VGA_TEXTMODE_LIGHTGREEN (10)
#define VGA_TEXTMODE_LIGHTCYAN (11)
#define VGA_TEXTMODE_LIGHTRED (12)
#define VGA_TEXTMODE_LIGHTPURPLE (13)
#define VGA_TEXTMODE_YELLOW (14)
#define VGA_TEXTMODE_WHITE (15)

#define VGA_TEXTMODE_DEFAULT_FG (VGA_TEXTMODE_GRAY)
#define VGA_TEXTMODE_DEFAULT_BG (VGA_TEXTMODE_BLACK)


#define vga_textmode_compute_color(fg, bg) ((char) ((char)0xf & fg) | ((char)0x70 & (bg << 4)))

/**
 * Protected mode video color bytes are arranged as follows:
 * |SBBBFFFF|
 *
 * Where:
 *  S is a special bit which is dependent on the current BIOS mode
 *  B are the background color bits
 *  F are the foreground color bits
 */
char vga_textmode_get_color_byte(const char fg, const char bg);

/**
 * Prints a single char to the display.
 *
 * Requires a formatted colorbyte
 */
void vga_textmode_print_char(const char c, const char colorbyte);

/**
 * Prints the given string to the display.
 *
 * fg and bg colors need to be one of the colors defined in the macros
 * of this file
 */
void vga_textmode_print_string(const char* s, const int fg, const int bg);

/**
 * Clears the current screen to all black
 */
void vga_textmode_clear_screen(void);

/**
 * Outputs a single character to the display in the default colors
 */
void vga_textmode_putc(const char c);

static inline size_t vga_textmode_index_from_coords(int x, int y) {
    assert(x >= 0 && x <= 80);
    assert(y >= 0 && y <= 25);

    return ((80 * y) + x) * 2;
}
