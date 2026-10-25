#ifndef SYS_ARCH_H
#define SYS_ARCH_H

#include "arch/cc.h"

typedef int sys_prot_t;

sys_prot_t sys_arch_protect(void);
void sys_arch_unprotect(sys_prot_t pval);
u32_t sys_now(void);

#endif
