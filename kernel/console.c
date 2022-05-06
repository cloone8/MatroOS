#include <x86-64/asm.h>
#include <kbdreg.h>
#include <string.h>
#include <assert.h>

#include <kernel/console.h>
#include <kernel/pic.h>
#include <kernel/output.h>

/***** General device-independent console code *****/
/* Here we manage the console input buffer,
 * where we stash characters received from the keyboard or serial port
 * whenever the corresponding interrupt occurs. */

#define CONSBUFSIZE 512

static struct {
    uint8_t buf[CONSBUFSIZE];
    uint32_t rpos;
    uint32_t wpos;
} cons;

/* called by device interrupt routines to feed input characters
 * into the circular console input buffer. */
static void cons_intr(int (*proc)(void))
{
    int c;

    while ((c = (*proc)()) != -1) {
        if (c == 0)
            continue;
        cons.buf[cons.wpos++] = c;
        if (cons.wpos == CONSBUFSIZE)
            cons.wpos = 0;
    }
}

/* return the next input character from the console, or 0 if none waiting */
int cons_getc(void)
{
    // TODO: Make this do something
    return 0;
}

/* Output a character to the console. */
static void cons_putc(int c)
{
    vga_textmode_putc((const char) c);
}

/* Initialize the console devices. */
void cons_init(void)
{
    vga_textmode_clear_screen();
}


/* `High'-level console I/O.  Used by readline and cprintf. */

void cputchar(int c)
{
    cons_putc(c);
}

int getchar(void)
{
    int c;

    while ((c = cons_getc()) == 0)
        /* do nothing */;
    return c;
}

int iscons(int fdnum)
{
    /* used by readline */
    return 1;
}
