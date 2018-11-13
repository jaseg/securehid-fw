
#include <cobs.h>

/*@ requires \valid(dst + (0..dstlen-1));
  @ requires \valid_read(src + (0..srclen-1));
  @ requires \separated(dst + (0..dstlen-1), src + (0..srclen-1));
  @
  @ behavior valid:
  @     assumes 0 <= srclen <= 254;
  @     assumes 0 <= dstlen <= 65535;
  @     assumes dstlen >= srclen+2;
  @     assigns dst[0..srclen+1];
  @     ensures \forall integer i; (0 <= i < srclen && \old(src[i]) != 0) ==> dst[i+1] == src[i];
  @     ensures \result == srclen+2;
  @     ensures \forall integer i; 0 <= i <= srclen ==> dst[i] != 0;
  @     ensures dst[srclen+1] == 0;
  @
  @ behavior invalid:
  @     assumes    srclen < 0 || srclen > 254
  @             || dstlen < 0 || dstlen > 65535
  @             || dstlen < srclen+2;
  @     assigns \nothing;
  @     ensures \result == -1;
  @
  @ complete behaviors;
  @ disjoint behaviors;
 @*/
ssize_t cobs_encode(char *dst, size_t dstlen, char *src, size_t srclen) {
    if (dstlen > 65535 || srclen > 254)
        return -1;
    //@ assert 0 <= dstlen <= 65535 && 0 <= srclen <= 254;

    if (dstlen < srclen+2)
        return -1;
    //@ assert 0 <= srclen < srclen+2 <= dstlen;

    size_t p = 0;
    /*@ loop invariant 0 <= p <= srclen+1;
      @ loop invariant \forall integer i; 0 <= i < p ==> dst[i] != 0;
      @ loop invariant \forall integer i; 0 < i < p ==> (src[i-1] != 0 ==> dst[i] == src[i-1]);
      @ loop assigns p, dst[0..srclen+1];
      @ loop variant srclen-p+1;
      @*/
    while (p <= srclen) {

        char val;
        if (p != 0 && src[p-1] != 0) {
            val = src[p-1];

        } else {
            size_t q = p;
            /*@ loop invariant 0 <= p <= q <= srclen;
              @ loop invariant \forall integer i; p <= i < q ==> src[i] != 0;
              @ loop assigns q;
              @ loop variant srclen-q;
              @*/
            while (q < srclen && src[q] != 0)
                q++;
            //@ assert q == srclen || src[q] == 0;
            //@ assert q <= srclen <= 254;
            val = (char)q-p+1;
            //@ assert val != 0;
        }

        dst[p] = val;
        p++;
    }

    dst[p] = 0;
    //@ assert p == srclen+1;

    return srclen+2;
}

int cobs_encode_incremental(void *f, int (*output)(void *f, char c), char *src, size_t srclen) {
    if (srclen > 254)
        return -1;
    //@ assert 0 <= srclen <= 254;

    size_t p = 0;
    /*@ loop invariant 0 <= p <= srclen+1;
      @ loop assigns p;
      @ loop variant srclen-p+1;
      @*/
    while (p <= srclen) {

        char val;
        if (p != 0 && src[p-1] != 0) {
            val = src[p-1];

        } else {
            size_t q = p;
            /*@ loop invariant 0 <= p <= q <= srclen;
              @ loop invariant \forall integer i; p <= i < q ==> src[i] != 0;
              @ loop assigns q;
              @ loop variant srclen-q;
              @*/
            while (q < srclen && src[q] != 0)
                q++;
            //@ assert q == srclen || src[q] == 0;
            //@ assert q <= srclen <= 254;
            val = (char)q-p+1;
            //@ assert val != 0;
        }

        int rv = output(f, val);
        if (rv)
            return rv;
        p++;
    }

    int rv = output(f, 0);
    if (rv)
        return rv;
    //@ assert p == srclen+1;

    return 0;
}

/*@ requires \valid(dst + (0..dstlen-1));
  @ requires \valid_read(src + (0..srclen-1));
  @ requires \separated(dst + (0..dstlen-1), src + (0..srclen-1));
  @ 
  @ behavior maybe_valid_frame:
  @     assumes 1 <= srclen <= dstlen <= 65535;
  @     assumes \exists integer j; j > 0 && \forall integer i; 0 <= i < j ==> src[i] != 0;
  @     assumes \exists integer i; 0 <= i < srclen && src[i] == 0;
  @     assigns dst[0..dstlen-1];
  @     ensures \result >= 0 || \result == -3;
  @     ensures \result >= 0 ==> src[\result+1] == 0;
  @     ensures \result >= 0 ==> (\forall integer i; 0 <= i < \result ==> src[i] != 0);
  @
  @ behavior invalid_frame:
  @     assumes 1 <= srclen <= dstlen <= 65535;
  @     assumes src[0] == 0 || \forall integer i; 0 <= i < srclen ==> src[i] != 0;
  @     assigns dst[0..dstlen-1];
  @     ensures \result == -2;
  @
  @ behavior invalid_buffers:
  @     assumes    dstlen < 0 || dstlen > 65535
  @             || srclen < 1 || srclen > 65535
  @             || dstlen < srclen;
  @     assigns \nothing;
  @     ensures \result == -1;
  @
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
ssize_t cobs_decode(char *dst, size_t dstlen, char *src, size_t srclen) {
    if (dstlen > 65535 || srclen > 65535)
        return -1;

    if (srclen < 1)
        return -1;

    if (dstlen < srclen)
        return -1;

    size_t p = 1;
    size_t c = (unsigned char)src[0];
    //@ assert 0 <= c < 256;
    //@ assert 0 <= c;
    //@ assert c < 256;
    if (c == 0)
        return -2; /* invalid framing. An empty frame would be [...] 00 01 00, not [...] 00 00 */
    //@ assert c >= 0;
    //@ assert c != 0;
    //@ assert c <= 257;
    //@ assert c > 0;
    //@ assert c >= 0 && c != 0 ==> c > 0;

    /*@ //loop invariant \forall integer i; 0 <= i <= p ==> (i == srclen || src[i] != 0);
      @ loop invariant \forall integer i; 1 <= i < p ==> src[i] != 0;
      @ loop invariant c > 0;
      @ loop invariant 1 <= p <= srclen <= dstlen <= 65535;
      @ loop invariant \separated(dst + (0..dstlen-1), src + (0..srclen-1));
      @ loop invariant \valid_read(src + (0..srclen-1));
      @ loop invariant \forall integer i; 1 <= i <= srclen ==> \valid(dst + i - 1);
      @ loop assigns dst[0..dstlen-1], p, c;
      @ loop variant srclen-p;
      @*/
    while (p < srclen && src[p]) {
        char val;
        c--;

        //@ assert src[p] != 0;
        if (c == 0) {
            c = (unsigned char)src[p];
            val = 0;
        } else {
            val = src[p];
        }

        //@ assert 0 <= p-1 <= dstlen-1;
        dst[p-1] = val;
        p++;
    }

    if (p == srclen)
        return -2; /* Invalid framing. The terminating null byte should always be present in the input buffer. */

    if (c != 1)
        return -3; /* Invalid framing. The skip counter does not hit the end of the frame. */

    //@ assert 0 < p <= srclen <= 65535;
    //@ assert src[p] == 0;
    //@ assert \forall integer i; 1 <= i < p ==> src[i] != 0;
    return p-1;
}

void cobs_decode_incremental_initialize(struct cobs_decode_state *state) {
    state->p = 0;
    state->c = 0;
}

int cobs_decode_incremental(struct cobs_decode_state *state, char *dst, size_t dstlen, char src) {
    if (state->p == 0) {
        if (src == 0)
            goto empty_errout; /* invalid framing. An empty frame would be [...] 00 01 00, not [...] 00 00 */
        state->c = (unsigned char)src;
        state->p++;
        return 0;
    }

    if (!src) {
        if (state->c != 1)
            goto errout; /* Invalid framing. The skip counter does not hit the end of the frame. */
        int rv = state->p-1;
        cobs_decode_incremental_initialize(state);
        return rv;
    }

    char val;
    state->c--;

    if (state->c == 0) {
        state->c = (unsigned char)src;
        val = 0;
    } else {
        val = src;
    }

    size_t pos = state->p-1;
    if (pos >= dstlen)
        return -2; /* output buffer too small */
    dst[pos] = val;
    state->p++;
    return 0;

errout:
    cobs_decode_incremental_initialize(state);
    return -1;

empty_errout:
    cobs_decode_incremental_initialize(state);
    return -3;
}

#ifdef VALIDATION
/*@ 
  @ requires 0 <= d < 256;
  @ assigns \nothing;
  @*/
size_t test(char foo, unsigned int d) {
    unsigned int c = (unsigned char)foo;
    if (c != 0) {
        //@ assert c < 256;
        //@ assert c >= 0;
        //@ assert c != 0;
        //@ assert c > 0;
    }
    if (d != 0) {
        //@ assert d >= 0;
        //@ assert d != 0;
        //@ assert d > 0;
    }
    return c + d;
}

#include <__fc_builtin.h>

void main(void) {
    char inbuf[254];
    char cobsbuf[256];
    char outbuf[256];

    size_t range = Frama_C_interval(0, sizeof(inbuf));
    Frama_C_make_unknown((char *)inbuf, range);

    cobs_encode(cobsbuf, sizeof(cobsbuf), inbuf, sizeof(inbuf));
    cobs_decode(outbuf, sizeof(outbuf), cobsbuf, sizeof(cobsbuf));
    
    //@ assert \forall integer i; 0 <= i < sizeof(inbuf) ==> outbuf[i] == inbuf[i];
}
#endif//VALIDATION

