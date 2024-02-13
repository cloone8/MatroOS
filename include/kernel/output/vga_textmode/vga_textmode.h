#pragma once

#include <assert.h>

#define VMEM ((char*)0xb8000)

#define VGA_TEXTMODE_BLACK (0x0)
#define VGA_TEXTMODE_BLUE (0x1)
#define VGA_TEXTMODE_GREEN (0x2)
#define VGA_TEXTMODE_CYAN (0x3)
#define VGA_TEXTMODE_RED (0x4)
#define VGA_TEXTMODE_PURPLE (0x5)
#define VGA_TEXTMODE_BROWN (0x6)
#define VGA_TEXTMODE_GRAY (0x7)
#define VGA_TEXTMODE_DARKGRAY (0x8)
#define VGA_TEXTMODE_LIGHTBLUE (0x9)
#define VGA_TEXTMODE_LIGHTGREEN (0xA)
#define VGA_TEXTMODE_LIGHTCYAN (0xB)
#define VGA_TEXTMODE_LIGHTRED (0xC)
#define VGA_TEXTMODE_LIGHTPURPLE (0xD)
#define VGA_TEXTMODE_YELLOW (0xE)
#define VGA_TEXTMODE_WHITE (0xF)

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
