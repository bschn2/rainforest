// RainForest hash algorithm
// Author: Bill Schneider
// Date: Feb 13th, 2018
//
// RainForest uses native integer operations which are extremely fast on
// modern 64-bit processors, significantly slower on 32-bit processors such
// as GPUs, and extremely slow if at all implementable on FPGAs and ASICs.
// It makes an intensive use of the L1 cache to maintain a heavy intermediary
// state favoring modern CPUs compared to GPUs (small L1 cache shared by many
// shaders) or FPGAs (very hard to implement the required low-latency cache)
// when scanning ranges for nonces. The purpose is to create a fair balance
// between all mining equipments, from mobile phones to extreme performance
// GPUs and to rule out farming factories relying on ASICs and FPGAs. The
// CRC32 instruction is used a lot as it is extremely fast on low-power ARM
// chips and allows such devices to rival high-end PCs mining performance.
//
// Tests on various devices have shown the following performance :
// +--------------------------------------------------------------------------+
// | CPU/GPU       Clock Threads Full hash  Nonce scan  Watts   Cost          |
// |               (MHz)         (80 bytes) (4 bytes)   total                 |
// | Core i7-6700k  4000      8   390 kH/s  1642 kH/s     200  ~$350+PC       |
// | Radeon RX560   1300   1024  1100 kH/s  1650 kH/s     300  ~$180+PC       |
// | RK3368 (8*A53) 1416      8   534 kH/s  1582 kH/s       6   $60 (Geekbox) |
// +--------------------------------------------------------------------------+
//
// Build instructions on Ubuntu 16.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.
//
// Note: always use the same options to build all files!
//

#include <stdint.h>
#include <string.h>
#include "rainforest.h"

// these archs are fine with unaligned reads
#if defined(__x86_64__)||defined(__aarch64__)
#define RF_UNALIGNED_LE64
#define RF_UNALIGNED_LE32
#elif defined(__i386__)||defined(__ARM_ARCH_7A__)
#define RF_UNALIGNED_LE32
#endif

#define RF256_INIT_CRC 20180213

// for aes2r_encrypt()
#include "rf_aes2r.c"

// for rf_crc32_32()
#include "rf_crc32.c"

// the table is used as an 8 bit-aligned array of uint64_t for the first word,
// and as a 16 bit-aligned array of uint64_t for the second word. It is filled
// with the sha256 of "RainForestProCpuAntiAsic", iterated over and over until
// the table is filled. The highest offset being ((uint16_t *)table)[255] we
// need to add 6 extra bytes at the end to read an uint64_t. Maybe calculated
// on a UNIX system with this loop :
//
//   ref="RainForestProCpuAntiAsic"
//   for ((i=0;i<18;i++)); do
//     set $(echo -n $ref|sha256sum)
//     echo $1|sed 's/\(..\)/0x\1,/g'
//     ref=$(printf $(echo $1|sed 's/\(..\)/\\x\1/g'))
//   done

static const uint8_t rf_table[256 * 2 + 6] = {
	0x8e,0xc1,0xa8,0x04,0x38,0x78,0x7c,0x54,0x29,0x23,0x1b,0x78,0x9f,0xf9,0x27,0x54,
	0x11,0x78,0x95,0xb6,0xaf,0x78,0x45,0x16,0x2b,0x9e,0x91,0xe8,0x97,0x25,0xf8,0x63,
	0x82,0x56,0xcf,0x48,0x6f,0x82,0x14,0x0d,0x61,0xbe,0x47,0xd1,0x37,0xee,0x30,0xa9,
	0x28,0x1e,0x4b,0xbf,0x07,0xcd,0x41,0xdf,0x23,0x21,0x12,0xb8,0x81,0x99,0x1d,0xe6,
	0x68,0xcf,0xfa,0x2d,0x8e,0xb9,0x88,0xa7,0x15,0xce,0x9e,0x2f,0xeb,0x1b,0x0f,0x67,
	0x20,0x68,0x6c,0xa9,0x5d,0xc1,0x7c,0x76,0xdf,0xbd,0x98,0x61,0xb4,0x14,0x65,0x40,
	0x1e,0x72,0x51,0x74,0x93,0xd3,0xad,0xbe,0x46,0x0a,0x25,0xfb,0x6a,0x5e,0x1e,0x8a,
	0x5a,0x03,0x3c,0xab,0x12,0xc2,0xd4,0x07,0x91,0xab,0xc9,0xdf,0x92,0x2c,0x85,0x6a,
	0xa6,0x25,0x1e,0x66,0x50,0x26,0x4e,0xa8,0xbd,0xda,0x88,0x1b,0x95,0xd4,0x00,0xeb,
	0x0d,0x1c,0x9b,0x3c,0x86,0xc7,0xb2,0xdf,0xb4,0x5a,0x36,0x15,0x8e,0x04,0xd2,0x54,
	0x79,0xd2,0x3e,0x3d,0x99,0x50,0xa6,0x12,0x4c,0x32,0xc8,0x51,0x14,0x4d,0x4b,0x0e,
	0xbb,0x17,0x80,0x8f,0xa4,0xc4,0x99,0x72,0xd7,0x14,0x4b,0xef,0xed,0x14,0xe9,0x17,
	0xfa,0x9b,0x5d,0x37,0xd6,0x2f,0xef,0x02,0xd6,0x71,0x0a,0xbd,0xc5,0x40,0x11,0x90,
	0x90,0x4e,0xb4,0x4c,0x72,0x51,0x7a,0xd8,0xba,0x30,0x4d,0x8c,0xe2,0x11,0xbb,0x6d,
	0x4b,0xbc,0x6f,0x14,0x0c,0x9f,0xfa,0x5e,0x66,0x40,0x45,0xcb,0x7d,0x1b,0x3a,0xc5,
	0x5e,0x9c,0x1e,0xcc,0xbd,0x16,0x3b,0xcf,0xfb,0x2a,0xd2,0x08,0x2a,0xf8,0x3d,0x46,
	0x93,0x90,0xb3,0x66,0x81,0x34,0x7f,0x6d,0x9b,0x8c,0x99,0x03,0xc5,0x27,0xa3,0xd9,
	0xce,0x90,0x88,0x0f,0x55,0xc3,0xa1,0x60,0x53,0xc8,0x0d,0x25,0xae,0x61,0xd9,0x72,
	0x48,0x1d,0x6c,0x61,0xd2,0x87,0xdd,0x3d,0x23,0xf5,0xde,0x93,0x39,0x4c,0x43,0x9a,
	0xf9,0x37,0xf2,0x61,0xd7,0xf8,0xea,0x65,0xf0,0xf1,0xde,0x3f,0x05,0x57,0x83,0x81,
	0xde,0x02,0x62,0x49,0xd4,0x32,0x7e,0x4a,0xd4,0x9f,0x40,0x7e,0xb9,0x91,0xb1,0x35,
	0xf7,0x62,0x3f,0x65,0x9e,0x4d,0x2b,0x10,0xde,0xd4,0x77,0x64,0x0f,0x84,0xad,0x92,
	0xe7,0xa3,0x8a,0x10,0xc1,0x14,0xeb,0x57,0xc4,0xad,0x8e,0xc2,0xc7,0x32,0xa3,0x7e,
	0x50,0x1f,0x7c,0xbb,0x2e,0x5f,0xf5,0x18,0x22,0xea,0xec,0x9d,0xa4,0x77,0xcd,0x85,
	0x04,0x2f,0x20,0x61,0x72,0xa7,0x0c,0x92,0x06,0x4d,0x01,0x70,0x9b,0x35,0xa1,0x27,
	0x32,0x6e,0xb9,0x78,0xe0,0xaa,0x5f,0x91,0xa6,0x51,0xe3,0x63,0xf8,0x97,0x2f,0x60,
	0xd9,0xfb,0x15,0xe5,0x59,0xcf,0x31,0x3c,0x61,0xc7,0xb5,0x61,0x2a,0x6b,0xdd,0xd1,
	0x09,0x70,0xc0,0xcf,0x94,0x7a,0xcc,0x31,0x94,0xb1,0xa2,0xf6,0x95,0xc0,0x38,0x3d,
	0xef,0x19,0x30,0x70,0xdd,0x62,0x32,0x8f,0x7c,0x30,0xb9,0x18,0xf8,0xe7,0x8f,0x0a,
	0xaa,0xb6,0x00,0x86,0xf2,0xe0,0x30,0x5f,0xa2,0xe8,0x00,0x8e,0x05,0xa0,0x22,0x18,
	0x9f,0x83,0xd4,0x3a,0x85,0x10,0xb9,0x51,0x8d,0x07,0xf0,0xb3,0xcd,0x9b,0x55,0xa1,
	0x14,0xce,0x0f,0xb2,0xcf,0xb8,0xce,0x2d,0xe6,0xe8,0x35,0x32,0x1f,0x22,0xb5,0xec,
	0xd0,0xb9,0x72,0xa8,0xb4,0x97
	//,0x6e,0x0a,0x47,0xcd,0x5a,0xf0,0xdc,0xeb,0xfd,0x46,
	//0xe5,0x6e,0x83,0xe6,0x1a,0xcc,0x4a,0x8b,0xa5,0x28,0x9e,0x50,0x48,0xa9,0xa2,0x6b,
};

// this is made of the last iteration of the rf_table (18th transformation)
static const uint8_t rf256_iv[32] = {
	0x78,0xe9,0x90,0xd3,0xb3,0xc8,0x9b,0x7b,0x0a,0xc4,0x86,0x6e,0x4e,0x38,0xb3,0x6b,
	0x33,0x68,0x7c,0xed,0x73,0x35,0x4b,0x0a,0x97,0x25,0x4c,0x77,0x7a,0xaa,0x61,0x1b
};

// mix the current state with the crc and return the new crc
static inline uint32_t rf_crc32x4(rf_u32 *state, uint32_t crc)
{
	crc = state[0] = rf_crc32_32(crc, state[0]);
	crc = state[1] = rf_crc32_32(crc, state[1]);
	crc = state[2] = rf_crc32_32(crc, state[2]);
	crc = state[3] = rf_crc32_32(crc, state[3]);
	return crc;
}

// add to _msg_ its own crc32. use -mcpu=cortex-a53+crc to enable native CRC
// instruction on ARM.
static inline uint64_t rf_add64_crc32(uint64_t msg)
{
	return msg + rf_crc32_64(0, msg);
}

// read 64 bit from possibly unaligned memory address _p_ in little endian mode
static inline uint64_t rf_memr64(const uint8_t *p)
{
#ifdef RF_UNALIGNED_LE64
	return *(uint64_t *)p;
#else
	uint64_t ret;
	int byte;
	for (ret = byte = 0; byte < 8; byte++)
		ret += (uint64_t)p[byte] << (byte * 8);
	return ret;
#endif
}

// return rainforest lower word entry for index
static inline uint64_t rf_wltable(uint8_t index)
{
	return rf_memr64(&rf_table[index]);
}

// return rainforest upper word entry for _index_
static inline uint64_t rf_whtable(uint8_t index)
{
	return rf_memr64(&rf_table[index * 2]);
}

// rotate left vector _v_ by _bits_ bits
static inline uint64_t rf_rotl64(uint64_t v, uint8_t bits)
{
#if !defined(__ARM_ARCH_8A) && !defined(__AARCH64EL__) && !defined(x86_64)
	bits &= 63;
#endif
	return (v << bits) | (v >> (64 - bits));
}

// rotate right vector _v_ by _bits_ bits
static inline uint64_t rf_rotr64(uint64_t v, uint8_t bits)
{
#if !defined(__ARM_ARCH_8A) && !defined(__AARCH64EL__) && !defined(x86_64)
	bits &= 63;
#endif
	return (v >> bits) | (v << (64 - bits));
}

// reverse all bytes in the word _v_
static inline uint64_t rf_bswap64(uint64_t v)
{
#if defined(__x86_64__) && !defined(_MSC_VER)
	__asm__("bswap %0":"+r"(v));
#elif defined(__aarch64__)
	__asm__("rev %0,%0\n":"+r"(v));
#else
	v = ((v & 0xff00ff00ff00ff00ULL) >> 8)  | ((v & 0x00ff00ff00ff00ffULL) << 8);
	v = ((v & 0xffff0000ffff0000ULL) >> 16) | ((v & 0x0000ffff0000ffffULL) << 16);
	v = (v >> 32) | (v << 32);
#endif
	return v;
}

// lookup _old_ in _rambox_, update it and perform a substitution if a matching
// value is found.
static inline uint32_t rf_rambox(rf256_ctx_t *ctx, uint64_t old)
{
	uint64_t * p, k;
	uint32_t idx;
	int loops;

	for (loops = 0; loops < RAMBOX_LOOPS; loops++) {
		old = rf_add64_crc32(old);
		idx = old & (RAMBOX_SIZE - 1);
		if (ctx->changes < RAMBOX_HIST)
			ctx->hist[ctx->changes++] = idx;
		p = &ctx->rambox[idx];
		k = *p;
		old += rf_rotr64(k, (uint8_t)(old/RAMBOX_SIZE));
		*p = (int64_t)old < 0 ? k : old;
	}
	return (uint32_t)old;
}

// write (_x_,_y_) at cell _cell_ for offset _ofs_
static inline void rf_w128(uint64_t *cell, size_t ofs, uint64_t x, uint64_t y)
{
#if defined(__ARM_ARCH_8A) || defined(__AARCH64EL__)
	// 128 bit at once is faster when exactly two parallelizable instructions are
	// used between two calls to keep the pipe full.
	__asm__ volatile("stp %0, %1, [%2,#%3]\n\t"
			 : /* no output */
			 : "r"(x), "r"(y), "r" (cell), "I" (ofs * 8));
#else
	cell[ofs + 0] = x;
	cell[ofs + 1] = y;
#endif
}

// initialize the ram box
static void rf_raminit(rf256_ctx_t *ctx)
{
	uint64_t pat1 = 0x0123456789ABCDEFULL;
	uint64_t pat2 = 0xFEDCBA9876543210ULL;
	uint64_t pat3;
	uint32_t pos;
	uint64_t *rambox = ctx->rambox;

	// Note: no need to mask the higher bits on armv8 nor x86 :
	//
	// From ARMv8's ref manual :
	//     The register that is specified for a shift can be 32-bit or
	//     64-bit. The amount to be shifted can be specified either as
	//     an immediate, that is up to register size minus one, or by
	//     a register where the value is taken only from the bottom five
	//     (modulo-32) or six (modulo-64) bits.
	//
	// Here we rotate pat2 by pat1's bits and put it into pat1, and in
	// parallel we rotate pat1 by pat2's bits and put it into pat2. Thus
	// the two data blocks are exchanged in addition to being rotated.
	// What is stored each time is the previous and the rotated blocks,
	// which only requires one rotate and a register rename.

	ctx->changes = 0;
	for (pos = 0; pos < RAMBOX_SIZE; pos += 16) {
		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x111;
		rf_w128(rambox + pos, 0, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x222;
		rf_w128(rambox + pos, 2, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x333;
		rf_w128(rambox + pos, 4, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x444;
		rf_w128(rambox + pos, 6, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x555;
		rf_w128(rambox + pos, 8, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x666;
		rf_w128(rambox + pos, 10, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, (uint8_t)pat3) + 0x777;
		rf_w128(rambox + pos, 12, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, (uint8_t)pat3) + 0x888;
		rf_w128(rambox + pos, 14, pat2, pat3);
	}
}

// exec the div/mod box. _v0_ and _v1_ must be aligned.
static inline void rf256_divbox(rf_u64 *v0, rf_u64 *v1)
{
	uint64_t pl, ql, ph, qh;

	//---- low word ----    ---- high word ----
	pl = ~*v0;              ph = ~*v1;
	ql = rf_bswap64(*v0);   qh = rf_bswap64(*v1);

	if (!pl || !ql)   { pl = ql = 0; }
	else if (pl > ql) { uint64_t p = pl; pl = p / ql; ql = p % ql; }
	else              { uint64_t p = pl; pl = ql / p; ql = ql % p; }

	if (!ph || !qh)   { ph = qh = 0; }
	else if (ph > qh) { uint64_t p = ph; ph = p / qh; qh = p % qh; }
	else              { uint64_t p = ph; ph = qh / p; qh = qh % p; }

	pl += qh;               ph += ql;
	*v0 -= pl;              *v1 -= ph;
}

// exec the rotation/add box. _v0_ and _v1_ must be aligned.
static inline void rf256_rotbox(rf_u64 *v0, rf_u64 *v1, uint8_t b0, uint8_t b1)
{
	uint64_t l, h;

	//---- low word ----       ---- high word ----
	l   = *v0;                 h   = *v1;
	l   = rf_rotr64(l, b0);    h   = rf_rotl64(h, b1);
	l  += rf_wltable(b0);      h  += rf_whtable(b1);
	b0  = (uint8_t)l;          b1  = (uint8_t)h;
	l   = rf_rotl64(l, b1);    h   = rf_rotr64(h, b0);
	b0  = (uint8_t)l;          b1  = (uint8_t)h;
	l   = rf_rotr64(l, b1);    h   = rf_rotl64(h, b0);
	*v0 = l;                   *v1 = h;
}

// mix the current state with the current crc
static inline uint32_t rf256_scramble(rf256_ctx_t *ctx)
{
	return ctx->crc = rf_crc32x4(ctx->hash.d, ctx->crc);
}

// mix the state with the crc and the pending text, and update the crc
static inline void rf256_inject(rf256_ctx_t *ctx)
{
	ctx->crc =
		(ctx->len & 3) == 0 ? rf_crc32_32(rf256_scramble(ctx), ctx->word):
		(ctx->len & 3) == 3 ? rf_crc32_24(rf256_scramble(ctx), ctx->word):
		(ctx->len & 3) == 2 ? rf_crc32_16(rf256_scramble(ctx), ctx->word):
		rf_crc32_8(rf256_scramble(ctx), ctx->word);
	ctx->word = 0;
}

// rotate the hash by 32 bits. Not using streaming instructions (SSE/NEON) is
// faster because the compiler can follow moves an use register renames.
static inline void rf256_rot32x256(rf_hash256_t *hash)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__ARM_ARCH_7A__)
	uint32_t t0, t1, t2;

	t0 = hash->d[0];
	t1 = hash->d[1];
	t2 = hash->d[2];
	hash->d[1] = t0;
	hash->d[2] = t1;

	t0 = hash->d[3];
	t1 = hash->d[4];
	hash->d[3] = t2;
	hash->d[4] = t0;

	t2 = hash->d[5];
	t0 = hash->d[6];
	hash->d[5] = t1;
	hash->d[6] = t2;

	t1 = hash->d[7];
	hash->d[7] = t0;
	hash->d[0] = t1;
#else
	uint32_t tmp = hash->d[7];

	memmove(&hash->d[1], &hash->d[0], 28);
	hash->d[0] = tmp;
#endif
}

// encrypt the first 128 bits of the hash using the last 128 bits as the key
static inline void rf256_aesenc(rf256_ctx_t *ctx)
{
	aes2r_encrypt((uint8_t *)ctx->hash.b, (uint8_t *)ctx->hash.b + 16);
}

// each new round consumes exactly 32 bits of text at once and perturbates
// 128 bits of output, 96 of which overlap with the previous round, and 32
// of which are new. With 5 rounds or more each output bit depends on every
// input bit.
static inline void rf256_one_round(rf256_ctx_t *ctx)
{
	uint64_t carry;

	rf256_rot32x256(&ctx->hash);

	carry = ((uint64_t)ctx->len << 32) + ctx->crc;
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);

	carry = rf_rambox(ctx, carry);
	rf256_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry), (uint8_t)(carry >> 56));
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);

	carry = rf_rambox(ctx, carry);
	rf256_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 8), (uint8_t)(carry >> 48));
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);

	carry = rf_rambox(ctx, carry);
	rf256_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 16), (uint8_t)(carry >> 40));
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_scramble(ctx);

	carry = rf_rambox(ctx, carry);
	rf256_rotbox(ctx->hash.q, ctx->hash.q + 1, (uint8_t)(carry >> 24), (uint8_t)(carry >> 32));
	rf256_scramble(ctx);
	rf256_divbox(ctx->hash.q, ctx->hash.q + 1);
	rf256_inject(ctx);
	rf256_aesenc(ctx);
	rf256_scramble(ctx);
}

// initialize the hash state
static void rf256_init(rf256_ctx_t *ctx, uint32_t seed)
{
	rf_raminit(ctx);
	memcpy(ctx->hash.b, rf256_iv, sizeof(ctx->hash.b));
	ctx->crc = seed;
	ctx->word = ctx->len = 0;
}

// update the hash context _ctx_ with _len_ bytes from message _msg_
static inline void rf256_update(rf256_ctx_t *ctx, const void *msg, size_t len)
{
	const uint8_t *msg8 = (uint8_t *)msg;

	while (len > 0) {
#ifdef RF_UNALIGNED_LE32
		if (!(ctx->len & 3) && len >= 4) {
			ctx->word = *(uint32_t *)msg8;
			ctx->len += 4;
			rf256_one_round(ctx);
			msg8 += 4;
			len  -= 4;
			continue;
		}
#endif
		ctx->word |= ((uint32_t)*msg8++) << (8 * (ctx->len++ & 3));
		len--;
		if (!(ctx->len & 3))
			rf256_one_round(ctx);
	}
}

// pad to the next 256-bit (32 bytes) boundary
static inline void rf256_pad256(rf256_ctx_t *ctx)
{
	const uint8_t pad256[32] = { 0, };
	uint32_t pad;

	pad = (32 - ctx->len) & 0xF;
	if (pad)
		rf256_update(ctx, pad256, pad);
}

// finalize the hash and copy the result into _out_ if not null (256 bits)
static inline void rf256_final(void *out, rf256_ctx_t *ctx)
{
	// pad to the next 256 bit boundary
	rf256_pad256(ctx);

	// always run 4 extra rounds to complete the last 128 bits
	rf256_one_round(ctx);
	rf256_one_round(ctx);
	rf256_one_round(ctx);
	rf256_one_round(ctx);

	if (out)
		memcpy(out, ctx->hash.b, 32);
}

// hash _len_ bytes from _in_ into _out_, using _seed_
void rf256_hash2(void *out, const void *in, size_t len, uint32_t seed)
{
	rf256_ctx_t ctx;

	rf256_init(&ctx, seed);
	rf256_update(&ctx, in, len);
	rf256_final(out, &ctx);
}

// hash _len_ bytes from _in_ into _out_
void rf256_hash(void *out, const void *in, size_t len)
{
	return rf256_hash2(out, in, len, RF256_INIT_CRC);
}
