#ifndef ARCH_CC_H
#define ARCH_CC_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <machine/endian.h>

#define LWIP_NO_STDINT_H 0

typedef uint8_t  u8_t;
typedef int8_t   s8_t;
typedef uint16_t u16_t;
typedef int16_t  s16_t;
typedef uint32_t u32_t;
typedef int32_t  s32_t;
typedef uintptr_t mem_ptr_t;
typedef int sys_prot_t;

#define LWIP_RAND() ((u32_t)rand())

#define LWIP_PLATFORM_DIAG(x) do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { printf("Assertion \"%s\" failed at line %d in %s\n", x, __LINE__, __FILE__); } while(0)

#define BYTE_ORDER LITTLE_ENDIAN

#endif
