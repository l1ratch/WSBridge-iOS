#include "arch/sys_arch.h"
#include <mach/mach_time.h>

static mach_timebase_info_data_t g_timebase;
static int g_timebase_init = 0;

u32_t sys_now(void) {
    if (!g_timebase_init) {
        mach_timebase_info(&g_timebase);
        g_timebase_init = 1;
    }
    uint64_t t = mach_absolute_time();
    // Convert to milliseconds
    uint64_t ms = t * g_timebase.numer / g_timebase.denom / 1000000ULL;
    return (u32_t)ms;
}

sys_prot_t sys_arch_protect(void) {
    // NO_SYS=1: single-threaded, no protection needed
    return 0;
}

void sys_arch_unprotect(sys_prot_t pval) {
    (void)pval;
}
