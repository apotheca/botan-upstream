/*
* curve25519-donna-c64.c from github.com/agl/curve25519-donna
* revision 80ad9b9930c9baef5829dd2a235b6b7646d32a8e
*/

/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Code released into the public domain.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation.
 */

#include <botan/curve25519.h>
#include <botan/mul128.h>
#include <botan/internal/donna128.h>
#include <botan/internal/ct_utils.h>
#include <botan/loadstor.h>

namespace Botan {

typedef byte u8;
typedef u64bit limb;
typedef limb felem[5];

typedef struct
   {
       limb* x;
       limb* z;
   } fmonty_pair_t;

typedef struct
   {
     fmonty_pair_t q;
     fmonty_pair_t q_dash;
     const limb* q_minus_q_dash;
   } fmonty_in_t;

typedef struct
   {
     fmonty_pair_t two_q;
     fmonty_pair_t q_plus_q_dash;
   } fmonty_out_t;


#if !defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
typedef donna128 uint128_t;
#endif

/* Sum two numbers: output += in */
static inline void
fsum(limb *output, const limb *in) {
  output[0] += in[0];
  output[1] += in[1];
  output[2] += in[2];
  output[3] += in[3];
  output[4] += in[4];
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!)
 *
 * Assumes that out[i] < 2**52
 * On return, out[i] < 2**55
 */
static inline void
fdifference_backwards(felem out, const felem in) {
  /* 152 is 19 << 3 */
  static const limb two54m152 = (static_cast<limb>(1) << 54) - 152;
  static const limb two54m8 = (static_cast<limb>(1) << 54) - 8;

  out[0] = in[0] + two54m152 - out[0];
  out[1] = in[1] + two54m8 - out[1];
  out[2] = in[2] + two54m8 - out[2];
  out[3] = in[3] + two54m8 - out[3];
  out[4] = in[4] + two54m8 - out[4];
}

/* Multiply a number by a scalar: output = in * scalar */
static inline void
fscalar_product(felem output, const felem in, const limb scalar) {
  uint128_t a = uint128_t(in[0]) * scalar;
  output[0] = a & 0x7ffffffffffff;

  a = uint128_t(in[1]) * scalar + carry_shift(a, 51);
  output[1] = a & 0x7ffffffffffff;

  a = uint128_t(in[2]) * scalar + carry_shift(a, 51);
  output[2] = a & 0x7ffffffffffff;

  a = uint128_t(in[3]) * scalar + carry_shift(a, 51);
  output[3] = a & 0x7ffffffffffff;

  a = uint128_t(in[4]) * scalar + carry_shift(a, 51);
  output[4] = a & 0x7ffffffffffff;

  output[0] += carry_shift(a, 51) * 19;
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * Assumes that in[i] < 2**55 and likewise for in2.
 * On return, output[i] < 2**52
 */
static inline void
fmul(felem output, const felem in2, const felem in) {
  uint128_t t[5];
  limb r0,r1,r2,r3,r4,s0,s1,s2,s3,s4,c;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  s0 = in2[0];
  s1 = in2[1];
  s2 = in2[2];
  s3 = in2[3];
  s4 = in2[4];

  t[0]  =  uint128_t(r0) * s0;
  t[1]  =  uint128_t(r0) * s1 + uint128_t(r1) * s0;
  t[2]  =  uint128_t(r0) * s2 + uint128_t(r2) * s0 + uint128_t(r1) * s1;
  t[3]  =  uint128_t(r0) * s3 + uint128_t(r3) * s0 + uint128_t(r1) * s2 + uint128_t(r2) * s1;
  t[4]  =  uint128_t(r0) * s4 + uint128_t(r4) * s0 + uint128_t(r3) * s1 + uint128_t(r1) * s3 + uint128_t(r2) * s2;

  r4 *= 19;
  r1 *= 19;
  r2 *= 19;
  r3 *= 19;

  t[0] += uint128_t(r4) * s1 + uint128_t(r1) * s4 + uint128_t(r2) * s3 + uint128_t(r3) * s2;
  t[1] += uint128_t(r4) * s2 + uint128_t(r2) * s4 + uint128_t(r3) * s3;
  t[2] += uint128_t(r4) * s3 + uint128_t(r3) * s4;
  t[3] += uint128_t(r4) * s4;

                  r0 = t[0] & 0x7ffffffffffff; c = carry_shift(t[0], 51);
  t[1] += c;      r1 = t[1] & 0x7ffffffffffff; c = carry_shift(t[1], 51);
  t[2] += c;      r2 = t[2] & 0x7ffffffffffff; c = carry_shift(t[2], 51);
  t[3] += c;      r3 = t[3] & 0x7ffffffffffff; c = carry_shift(t[3], 51);
  t[4] += c;      r4 = t[4] & 0x7ffffffffffff; c = carry_shift(t[4], 51);
  r0 +=   c * 19; c = carry_shift(r0, 51); r0 = r0 & 0x7ffffffffffff;
  r1 +=   c;      c = carry_shift(r1, 51); r1 = r1 & 0x7ffffffffffff;
  r2 +=   c;

  output[0] = r0;
  output[1] = r1;
  output[2] = r2;
  output[3] = r3;
  output[4] = r4;
}

static inline void fsquare_times(felem output, const felem in, limb count) {
  uint128_t t[5];
  limb r0,r1,r2,r3,r4,c;
  limb d0,d1,d2,d4,d419;

  r0 = in[0];
  r1 = in[1];
  r2 = in[2];
  r3 = in[3];
  r4 = in[4];

  do {
    d0 = r0 * 2;
    d1 = r1 * 2;
    d2 = r2 * 2 * 19;
    d419 = r4 * 19;
    d4 = d419 * 2;

    t[0] = uint128_t(r0) * r0 + uint128_t(d4) * r1 + uint128_t(d2) * (r3     );
    t[1] = uint128_t(d0) * r1 + uint128_t(d4) * r2 + uint128_t(r3) * (r3 * 19);
    t[2] = uint128_t(d0) * r2 + uint128_t(r1) * r1 + uint128_t(d4) * (r3     );
    t[3] = uint128_t(d0) * r3 + uint128_t(d1) * r2 + uint128_t(r4) * (d419   );
    t[4] = uint128_t(d0) * r4 + uint128_t(d1) * r3 + uint128_t(r2) * (r2     );

                    r0 = t[0] & 0x7ffffffffffff; c = carry_shift(t[0], 51);
    t[1] += c;      r1 = t[1] & 0x7ffffffffffff; c = carry_shift(t[1], 51);
    t[2] += c;      r2 = t[2] & 0x7ffffffffffff; c = carry_shift(t[2], 51);
    t[3] += c;      r3 = t[3] & 0x7ffffffffffff; c = carry_shift(t[3], 51);
    t[4] += c;      r4 = t[4] & 0x7ffffffffffff; c = carry_shift(t[4], 51);
    r0 +=   c * 19; c = r0 >> 51; r0 = r0 & 0x7ffffffffffff;
    r1 +=   c;      c = r1 >> 51; r1 = r1 & 0x7ffffffffffff;
    r2 +=   c;
  } while(--count);

  output[0] = r0;
  output[1] = r1;
  output[2] = r2;
  output[3] = r3;
  output[4] = r4;
}

/* Load a little-endian 64-bit number  */
static limb
load_limb(const u8 *in) {
  return load_le<u64bit>(in, 0);
}

static void
store_limb(u8 *out, limb in) {
  store_le(in, out);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
fexpand(limb *output, const u8 *in) {
  output[0] = load_limb(in) & 0x7ffffffffffff;
  output[1] = (load_limb(in+6) >> 3) & 0x7ffffffffffff;
  output[2] = (load_limb(in+12) >> 6) & 0x7ffffffffffff;
  output[3] = (load_limb(in+19) >> 1) & 0x7ffffffffffff;
  output[4] = (load_limb(in+24) >> 12) & 0x7ffffffffffff;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void
fcontract(u8 *output, const felem input) {
  uint128_t t[5];

  t[0] = input[0];
  t[1] = input[1];
  t[2] = input[2];
  t[3] = input[3];
  t[4] = input[4];

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;

  /* now t is between 0 and 2^255-1, properly carried. */
  /* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */

  t[0] += 19;

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[0] += (t[4] >> 51) * 19; t[4] &= 0x7ffffffffffff;

  /* now between 19 and 2^255-1 in both cases, and offset by 19. */

  t[0] += 0x8000000000000 - 19;
  t[1] += 0x8000000000000 - 1;
  t[2] += 0x8000000000000 - 1;
  t[3] += 0x8000000000000 - 1;
  t[4] += 0x8000000000000 - 1;

  /* now between 2^255 and 2^256-20, and offset by 2^255. */

  t[1] += t[0] >> 51; t[0] &= 0x7ffffffffffff;
  t[2] += t[1] >> 51; t[1] &= 0x7ffffffffffff;
  t[3] += t[2] >> 51; t[2] &= 0x7ffffffffffff;
  t[4] += t[3] >> 51; t[3] &= 0x7ffffffffffff;
  t[4] &= 0x7ffffffffffff;

  store_limb(output,    combine_lower(t[0], 0, t[1], 51));
  store_limb(output+8,  combine_lower(t[1], 13, t[2], 38));
  store_limb(output+16, combine_lower(t[2], 26, t[3], 25));
  store_limb(output+24, combine_lower(t[3], 39, t[4], 12));
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   result.two_q (2*Q): long form
 *   result.q_plus_q_dash (Q + Q): long form
 *   in.q: short form, destroyed
 *   in.q_dash: short form, destroyed
 *   in.q_minus_q_dash: short form, preserved
 */
static void
fmonty(fmonty_out_t& result, fmonty_in_t& in)
{
  limb origx[5], origxprime[5], zzz[5], xx[5], zz[5], xxprime[5],
       zzprime[5], zzzprime[5];

  copy_mem(origx, in.q.x, 5);
  fsum(in.q.x, in.q.z);
  fdifference_backwards(in.q.z, origx);  // does x - z

  copy_mem(origxprime, in.q_dash.x, 5);
  fsum(in.q_dash.x, in.q_dash.z);
  fdifference_backwards(in.q_dash.z, origxprime);
  fmul(xxprime, in.q_dash.x, in.q.z);
  fmul(zzprime, in.q.x, in.q_dash.z);
  copy_mem(origxprime, xxprime, 5);
  fsum(xxprime, zzprime);
  fdifference_backwards(zzprime, origxprime);
  fsquare_times(result.q_plus_q_dash.x, xxprime, 1);
  fsquare_times(zzzprime, zzprime, 1);
  fmul(result.q_plus_q_dash.z, zzzprime, in.q_minus_q_dash);

  fsquare_times(xx, in.q.x, 1);
  fsquare_times(zz, in.q.z, 1);
  fmul(result.two_q.x, xx, zz);
  fdifference_backwards(zz, xx);  // does zz = xx - zz
  fscalar_product(zzz, zz, 121665);
  fsum(zzz, xx);
  fmul(result.two_q.z, zz, zzz);
}

// -----------------------------------------------------------------------------
// Maybe swap the contents of two limb arrays (@a and @b), each @len elements
// long. Perform the swap iff @swap is non-zero.
//
// This function performs the swap without leaking any side-channel
// information.
// -----------------------------------------------------------------------------
static void
swap_conditional(limb a[5], limb b[5], limb iswap) {
  unsigned i;
  const limb swap = static_cast<limb>(-iswap);

  for (i = 0; i < 5; ++i) {
    const limb x = swap & (a[i] ^ b[i]);
    a[i] ^= x;
    b[i] ^= x;
  }
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form)
 */
static void
cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q) {
  limb a[5] = {0}, b[5] = {1}, c[5] = {1}, d[5] = {0};
  limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
  limb e[5] = {0}, f[5] = {1}, g[5] = {0}, h[5] = {1};
  limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

  unsigned i, j;

  copy_mem(nqpqx, q, 5);

  for (i = 0; i < 32; ++i) {
    u8 byteval = n[31 - i];
    for (j = 0; j < 8; ++j) {
      const limb bit = byteval >> 7;

      swap_conditional(nqx, nqpqx, bit);
      swap_conditional(nqz, nqpqz, bit);

      fmonty_out_t result { nqx2, nqz2, nqpqx2, nqpqz2 };
      fmonty_in_t in { nqx, nqz, nqpqx, nqpqz, q };
      fmonty(result, in);
      swap_conditional(nqx2, nqpqx2, bit);
      swap_conditional(nqz2, nqpqz2, bit);

      t = nqx;
      nqx = nqx2;
      nqx2 = t;
      t = nqz;
      nqz = nqz2;
      nqz2 = t;
      t = nqpqx;
      nqpqx = nqpqx2;
      nqpqx2 = t;
      t = nqpqz;
      nqpqz = nqpqz2;
      nqpqz2 = t;

      byteval <<= 1;
    }
  }

  copy_mem(resultx, nqx, 5);
  copy_mem(resultz, nqz, 5);
}


// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code, tightened a little
// -----------------------------------------------------------------------------
static void
crecip(felem out, const felem z) {
  felem a,t0,b,c;

  /* 2 */ fsquare_times(a, z, 1); // a = 2
  /* 8 */ fsquare_times(t0, a, 2);
  /* 9 */ fmul(b, t0, z); // b = 9
  /* 11 */ fmul(a, b, a); // a = 11
  /* 22 */ fsquare_times(t0, a, 1);
  /* 2^5 - 2^0 = 31 */ fmul(b, t0, b);
  /* 2^10 - 2^5 */ fsquare_times(t0, b, 5);
  /* 2^10 - 2^0 */ fmul(b, t0, b);
  /* 2^20 - 2^10 */ fsquare_times(t0, b, 10);
  /* 2^20 - 2^0 */ fmul(c, t0, b);
  /* 2^40 - 2^20 */ fsquare_times(t0, c, 20);
  /* 2^40 - 2^0 */ fmul(t0, t0, c);
  /* 2^50 - 2^10 */ fsquare_times(t0, t0, 10);
  /* 2^50 - 2^0 */ fmul(b, t0, b);
  /* 2^100 - 2^50 */ fsquare_times(t0, b, 50);
  /* 2^100 - 2^0 */ fmul(c, t0, b);
  /* 2^200 - 2^100 */ fsquare_times(t0, c, 100);
  /* 2^200 - 2^0 */ fmul(t0, t0, c);
  /* 2^250 - 2^50 */ fsquare_times(t0, t0, 50);
  /* 2^250 - 2^0 */ fmul(t0, t0, b);
  /* 2^255 - 2^5 */ fsquare_times(t0, t0, 5);
  /* 2^255 - 21 */ fmul(out, t0, a);
}

int
curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint) {

  CT::poison(secret, 32);
  CT::poison(basepoint, 32);

  limb bp[5], x[5], z[5], zmone[5];
  uint8_t e[32];
  int i;

  for (i = 0;i < 32;++i) e[i] = secret[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  fexpand(bp, basepoint);
  cmult(x, z, e, bp);
  crecip(zmone, z);
  fmul(z, x, zmone);
  fcontract(mypublic, z);

  CT::unpoison(secret, 32);
  CT::unpoison(basepoint, 32);
  CT::unpoison(mypublic, 32);
  return 0;
}

}
