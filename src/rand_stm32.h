#ifndef __RAND_STM32_H__
#define __RAND_STM32_H__

#include <stdint.h>
#include <unistd.h>

#define BLAKE2S_HASH_SIZE 32

void rand_init(void);

#endif
