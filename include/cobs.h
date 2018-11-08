#ifndef __COBS_H__
#define __COBS_H__

#include <stdint.h>
#include <unistd.h>
#include <string.h>


struct cobs_decode_state {
    size_t p;
    size_t c;
};


ssize_t cobs_encode(char *dst, size_t dstlen, char *src, size_t srclen);
ssize_t cobs_decode(char *dst, size_t dstlen, char *src, size_t srclen);

int cobs_encode_incremental(void *f, int (*output)(void *, char), char *src, size_t srclen);

void cobs_decode_incremental_initialize(struct cobs_decode_state *state);
int cobs_decode_incremental(struct cobs_decode_state *state, char *dst, size_t dstlen, char src);

#endif//__COBS_H__
