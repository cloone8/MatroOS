/*
 * Simple implementation of cprintf console output for the kernel, based on
 * printfmt() and the kernel console's cputchar().
 */

#include <types.h>
#include <cpu.h>
#include <spinlock.h>
#include <stdio.h>
#include <stdarg.h>

#if !defined(USE_BIG_KERNEL_LOCK) || defined(DEBUG_CPU_LOCKS_MODE)
struct spinlock console_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "console_lock",
#endif
};
#endif

static void putch(int ch, int *cnt)
{
	cputchar(ch);
	*cnt++;
}

#ifdef DEBUG_MODE
static int vcprintf_nolock(const char *fmt, va_list ap) {
	int cnt = 0;

	vprintfmt((void*)putch, &cnt, fmt, ap);

	return cnt;
}
#endif

int vcprintf(const char *fmt, va_list ap)
{
	int cnt = 0;

	#if !defined(USE_BIG_KERNEL_LOCK) || defined(DEBUG_CPU_LOCKS_MODE)
		#ifdef DEBUG_CPU_LOCKS_MODE
			__spin_lock(&console_lock, __FILE__, __LINE__, 0);
		#else
			spin_lock(&console_lock);
		#endif
	#endif

	vprintfmt((void*)putch, &cnt, fmt, ap);

	#if !defined(USE_BIG_KERNEL_LOCK) || defined(DEBUG_CPU_LOCKS_MODE)
		#ifdef DEBUG_CPU_LOCKS_MODE
			__spin_unlock(&console_lock, __FILE__, __LINE__, 0);
		#else
			spin_unlock(&console_lock);
		#endif
	#endif

	return cnt;
}

int cprintf(const char *fmt, ...)
{
	va_list ap;
	int cnt;

	va_start(ap, fmt);
	cnt = vcprintf(fmt, ap);
	va_end(ap);

	return cnt;
}

#ifdef DEBUG_MODE
int cprintf_dbg(const char* module, const char* fmt, ...) {
	va_list ap;
	int cnt;

	#if !defined(USE_BIG_KERNEL_LOCK) || defined(DEBUG_CPU_LOCKS_MODE)
		#ifdef DEBUG_CPU_LOCKS_MODE
			__spin_lock(&console_lock, __FILE__, __LINE__, 0);
		#else
			spin_lock(&console_lock);
		#endif
	#endif

	va_start(ap, fmt);
	cnt = vcprintf_nolock("[DEBUG] ", ap);
	cnt += vcprintf_nolock(module, ap);
	cnt += vcprintf_nolock(fmt, ap);
	va_end(ap);

	#if !defined(USE_BIG_KERNEL_LOCK) || defined(DEBUG_CPU_LOCKS_MODE)
		#ifdef DEBUG_CPU_LOCKS_MODE
			__spin_unlock(&console_lock, __FILE__, __LINE__, 0);
		#else
			spin_unlock(&console_lock);
		#endif
	#endif

	return cnt;
}
#endif
