/*
 * Rainforest kernel implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 * Copyright (c) 2018 Bill Schneider
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 */

#pragma OPENCL EXTENSION cl_amd_printf : enable
#pragma OPENCL EXTENSION cl_intel_printf : enable

#ifndef RAINFOREST_CL
#define RAINFOREST_CL

#define RFV2_RAMBOX_SIZE (96*1024*1024/8)

// Author: Bill Schneider
// Created: Feb 13th, 2018
// Updated: Apr 21th, 2019
//
// RainForest uses native integer operations which are extremely fast on
// modern 64-bit processors, significantly slower on 32-bit processors such
// as GPUs, and extremely slow if at all implementable on FPGAs and ASICs.
// It makes an intensive use of the L1 cache to maintain a heavy intermediary
// state favoring modern CPUs compared to GPUs (small L1 cache shared by many
// shaders) or FPGAs (very hard to implement the required low-latency cache)
// when scanning ranges for nonces. Finally, it uses 96 MB of work
// area per thread in order to incur a cost to highly parallel processors such
// as high-end GPUs. The purpose is to create a fair balance between all mining
// equipments, from mobile phones to extreme performance GPUs and to rule out
// farming factories relying on ASICs, FPGAs, or any other very expensive
// solution. The CRC32 instruction is used a lot as it is extremely fast on
// low-power ARM chips and allows such devices to rival high-end PCs mining
// performance. Note that CRC32 is not used for security at all, only to
// disturb data.

/////////////////////////////// same as rf_aes2r.c ///////////////////////////

/* Rijndael's substitution box for sub_bytes step */
__constant static const uchar SBOX[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* shifts to do for shift_rows step */
__constant static const uchar shifts[16] = {
	 0,  5, 10, 15,
	 4,  9, 14,  3,
	 8, 13,  2,  7,
	12,  1,  6, 11
};

/* add the round key to the state with simple XOR operation */
static void add_round_key(uchar * state, uchar * rkey)
{
	uchar i;

	for (i = 0; i < 16; i++)
		state[i] ^= rkey[i];
}

/* substitute all bytes using Rijndael's substitution box */
static void sub_bytes(uchar * state)
{
	uchar i;

	for (i = 0; i < 16; i++)
		state[i] = SBOX[state[i]];
}

/* imagine the state not as 1-dimensional, but a 4x4 grid;
 * this step shifts the rows of this grid around */
static void shift_rows(uchar * state)
{
	uchar temp[16];
	uchar i;

	for (i = 0; i < 16; i++)
		temp[i] = state[shifts[i]];

	for (i = 0; i < 16; i++)
		state[i] = temp[i];
}

/* mix columns */
static void mix_columns(uchar * state)
{
	uchar a[4];
	uchar b[4];
	uchar h, i, k;

	for (k = 0; k < 4; k++) {
		for (i = 0; i < 4; i++) {
			a[i] = state[i + 4 * k];
			h = state[i + 4 * k] & 0x80; /* hi bit */
			b[i] = state[i + 4 * k] << 1;

			if (h == 0x80)
				b[i] ^= 0x1b; /* Rijndael's Galois field */
		}

		state[4 * k]     = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		state[1 + 4 * k] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		state[2 + 4 * k] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		state[3 + 4 * k] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
	}
}


/* key schedule stuff */

/* simple function to rotate 4 byte array */
static inline uint rotate32(uint in)
{
#if __ENDIAN_LITTLE__
	return rotate(in, (uint)24);
#else
	return rotate(in, (uint)8);
#endif
	return in;
}

/* key schedule core operation */
static inline uint sbox(uint in, uchar n)
{
	in = (SBOX[in & 255]) | (SBOX[(in >> 8) & 255] << 8) | (SBOX[(in >> 16) & 255] << 16) | (SBOX[(in >> 24) & 255] << 24);
#if __ENDIAN_LITTLE__
	in ^= n;
#else
	in ^= n << 24;
#endif
	return in;
}

// this version is optimized for exactly two rounds.
// _state_ must be 16-byte aligned.
static void aes2r_encrypt(uchar * state, uchar * key)
{
	uint key_schedule[12] __attribute__((aligned(16)));
	uint t;

	/* initialize key schedule; its first 16 bytes are the key */
	*(uint4 *)key_schedule = *(uint4 *)key;
	t = key_schedule[3];

	t = rotate32(t);
	t = sbox(t, 1);
	t = key_schedule[4]  = key_schedule[0] ^ t;
	t = key_schedule[5]  = key_schedule[1] ^ t;
	t = key_schedule[6]  = key_schedule[2] ^ t;
	t = key_schedule[7]  = key_schedule[3] ^ t;

	t = rotate32(t);
	t = sbox(t, 2);
	t = key_schedule[8]  = key_schedule[4] ^ t;
	t = key_schedule[9]  = key_schedule[5] ^ t;
	t = key_schedule[10] = key_schedule[6] ^ t;
	t = key_schedule[11] = key_schedule[7] ^ t;

	/* first round of the algorithm */
	add_round_key(state, (void*)&key_schedule[0]);
	sub_bytes(state);
	shift_rows(state);
	mix_columns(state);
	add_round_key(state, (void*)&key_schedule[4]);

	/* final round of the algorithm */
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, (void*)&key_schedule[8]);
}

/////////////////////////////// same as rf_crc32.c ///////////////////////////

// crc32 lookup tables
__constant static const uint rf_crc32_table[256] = {
	/* 0x00 */ 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
	/* 0x04 */ 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	/* 0x08 */ 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	/* 0x0c */ 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	/* 0x10 */ 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	/* 0x14 */ 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	/* 0x18 */ 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
	/* 0x1c */ 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	/* 0x20 */ 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	/* 0x24 */ 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	/* 0x28 */ 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
	/* 0x2c */ 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	/* 0x30 */ 0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
	/* 0x34 */ 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	/* 0x38 */ 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	/* 0x3c */ 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	/* 0x40 */ 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
	/* 0x44 */ 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	/* 0x48 */ 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
	/* 0x4c */ 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	/* 0x50 */ 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	/* 0x54 */ 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	/* 0x58 */ 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
	/* 0x5c */ 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	/* 0x60 */ 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	/* 0x64 */ 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	/* 0x68 */ 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	/* 0x6c */ 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	/* 0x70 */ 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
	/* 0x74 */ 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	/* 0x78 */ 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
	/* 0x7c */ 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	/* 0x80 */ 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	/* 0x84 */ 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	/* 0x88 */ 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	/* 0x8c */ 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	/* 0x90 */ 0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
	/* 0x94 */ 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	/* 0x98 */ 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	/* 0x9c */ 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	/* 0xa0 */ 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
	/* 0xa4 */ 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	/* 0xa8 */ 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
	/* 0xac */ 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	/* 0xb0 */ 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	/* 0xb4 */ 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	/* 0xb8 */ 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
	/* 0xbc */ 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	/* 0xc0 */ 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
	/* 0xc4 */ 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	/* 0xc8 */ 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	/* 0xcc */ 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	/* 0xd0 */ 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
	/* 0xd4 */ 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	/* 0xd8 */ 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	/* 0xdc */ 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	/* 0xe0 */ 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	/* 0xe4 */ 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	/* 0xe8 */ 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
	/* 0xec */ 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	/* 0xf0 */ 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
	/* 0xf4 */ 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	/* 0xf8 */ 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	/* 0xfc */ 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

static inline uint rf_crc32_32(uint crc, uint msg)
{
	crc = crc ^ msg;
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	return crc;
}

static inline uint rf_crc32_8(uint crc, uchar msg)
{
	crc = crc ^ msg;
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	return crc;
}

static inline ulong rf_crc32_64(uint crc, ulong msg)
{
	crc ^= (uint)msg;
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);

	crc ^= msg >> 32;
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	crc = rf_crc32_table[crc & 0xff] ^ (crc >> 8);
	return crc;
}

static inline uint rf_crc32_mem(uint crc, const void *msg, size_t len)
{
	const uchar *msg8 = (const uchar *)msg;

	while (len--) {
		crc = rf_crc32_8(crc, *msg8++);
	}
	return crc;
}

/////////////////////////////// same as rfv2_core.c ///////////////////////////

// these archs are fine with unaligned reads
#define RF_UNALIGNED_LE64

#define RFV2_INIT_CRC 20180213

#ifndef RF_ALIGN
#define RF_ALIGN(x) __attribute__((aligned(x)))
#endif

#define RFV2_RAMBOX_HIST 1536

typedef union {
	uchar  b[32];
	ushort w[16];
	uint   d[8];
	ulong  q[4];
} hash256_t;

typedef struct RF_ALIGN(16) rfv2_ctx {
	uint word;  // LE pending message
	uint len;   // total message length
	uint crc;
	ushort changes; // must remain lower than RFV2_RAMBOX_HIST
	ushort left_bits; // adjust rambox probability
	__global ulong *rambox;
	uint rb_o;    // rambox offset
	uint rb_l;    // rambox length
	hash256_t RF_ALIGN(32) hash;
	uint  hist[RFV2_RAMBOX_HIST];
	ulong prev[RFV2_RAMBOX_HIST];
} rfv2_ctx_t;

// the table is used as an 8 bit-aligned array of ulong for the first word,
// and as a 16 bit-aligned array of ulong for the second word. It is filled
// with the sha256 of "RainForestProCpuAntiAsic", iterated over and over until
// the table is filled. The highest offset being ((ushort *)table)[255] we
// need to add 6 extra bytes at the end to read an ulong. Maybe calculated
// on a UNIX system with this loop :
//
//   ref="RainForestProCpuAntiAsic"
//   for ((i=0;i<18;i++)); do
//     set $(echo -n $ref|sha256sum)
//     echo $1|sed 's/\(..\)/0x\1,/g'
//     ref=$(printf $(echo $1|sed 's/\(..\)/\\x\1/g'))
//   done

__constant static const uchar rfv2_table[256*2+6] = {
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

// this is made of the last iteration of the rfv2_table (18th transformation)
__constant static const uchar rfv2_iv[32] = {
	0x78,0xe9,0x90,0xd3,0xb3,0xc8,0x9b,0x7b,0x0a,0xc4,0x86,0x6e,0x4e,0x38,0xb3,0x6b,
	0x33,0x68,0x7c,0xed,0x73,0x35,0x4b,0x0a,0x97,0x25,0x4c,0x77,0x7a,0xaa,0x61,0x1b
};

static inline uint rf_crc32x4(uint *state, uint crc)
{
	crc = state[0] = rf_crc32_32(crc, state[0]);
	crc = state[1] = rf_crc32_32(crc, state[1]);
	crc = state[2] = rf_crc32_32(crc, state[2]);
	crc = state[3] = rf_crc32_32(crc, state[3]);
	return crc;
}

static inline ulong rf_add64_crc32(ulong msg)
{
	return msg + rf_crc32_64(0, msg);
}

static inline ulong rf_memr64(__constant const uchar *p)
{
#ifdef RF_UNALIGNED_LE64
	return *(__constant const ulong *)p;
#else
	ulong ret;
	int byte;

	for (ret = byte = 0; byte < 8; byte++)
		ret += (ulong)p[byte] << (byte * 8);
	return ret;
#endif
}

static inline ulong rf_wltable(uchar index)
{
	return rf_memr64(&rfv2_table[index]);
}

static inline ulong rf_whtable(uchar index)
{
	return rf_memr64(&rfv2_table[index * 2]);
}

static inline ulong rf_rotl64(ulong v, uchar bits)
{
#if 1
	return rotate(v, (ulong)bits);
#else
	return (v << bits) | (v >> (-bits & 63));
#endif
}

static inline ulong rf_rotr64(ulong v, uchar bits)
{
#if 1
	return rotate(v, (ulong)(-bits & 63));
#else
	return (v >> bits) | (v << (-bits & 63));
#endif
}

static inline ulong rf_bswap64(ulong v)
{
#if 1
	v = as_ulong(as_uchar8(v).s76543210);
#else
	v = ((v & 0xff00ff00ff00ff00ULL) >> 8)  | ((v & 0x00ff00ff00ff00ffULL) << 8);
	v = ((v & 0xffff0000ffff0000ULL) >> 16) | ((v & 0x0000ffff0000ffffULL) << 16);
	v = (v >> 32) | (v << 32);
#endif
	return v;
}

static inline ulong rf_revbit64(ulong v)
{
	v = ((v & 0xaaaaaaaaaaaaaaaa) >> 1) | ((v & 0x5555555555555555) << 1);
	v = ((v & 0xcccccccccccccccc) >> 2) | ((v & 0x3333333333333333) << 2);
	v = ((v & 0xf0f0f0f0f0f0f0f0) >> 4) | ((v & 0x0f0f0f0f0f0f0f0f) << 4);
	return rf_bswap64(v);
}

static inline ulong __builtin_clrsbl(long x)
{
	if (x < 0)
		return clz(~(x << 1));
	else
		return clz(x << 1);
}

static inline void rf_w128(__global ulong *cell, ulong ofs, ulong x, ulong y)
{
	cell[ofs + 0] = x;
	cell[ofs + 1] = y;
}

static inline ulong rfv2_rambox(rfv2_ctx_t *ctx, ulong old)
{
	__global ulong *p;
	ulong k;
	uint idx;

	k = old;
	old = rf_add64_crc32(old);
	old ^= rf_revbit64(k);
	if (__builtin_clrsbl(old) >= ctx->left_bits) {
		idx = ctx->rb_o + old % ctx->rb_l;
		p = &ctx->rambox[idx];
		k = *p;
		old += rf_rotr64(k, old / ctx->rb_l);
		*p = old;
		if (ctx->changes < RFV2_RAMBOX_HIST) {
			ctx->hist[ctx->changes] = idx;
			ctx->prev[ctx->changes] = k;
			ctx->changes++;
		}
	}
	return old;
}

static void rfv2_raminit(__global ulong *rambox)
{
	ulong pat1 = 0x0123456789ABCDEFULL;
	ulong pat2 = 0xFEDCBA9876543210ULL;
	ulong pat3;
	ulong pos;

	for (pos = 0; pos < RFV2_RAMBOX_SIZE; pos += 16) {
		pat3 = pat1;
		pat1 = rf_rotr64(pat2, pat3) + 0x111;
		rf_w128(rambox + pos, 0, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, pat3) + 0x222;
		rf_w128(rambox + pos, 2, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, pat3) + 0x333;
		rf_w128(rambox + pos, 4, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, pat3) + 0x444;
		rf_w128(rambox + pos, 6, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, pat3) + 0x555;
		rf_w128(rambox + pos, 8, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, pat3) + 0x666;
		rf_w128(rambox + pos, 10, pat2, pat3);

		pat3 = pat1;
		pat1 = rf_rotr64(pat2, pat3) + 0x777;
		rf_w128(rambox + pos, 12, pat1, pat3);

		pat3 = pat2;
		pat2 = rf_rotr64(pat1, pat3) + 0x888;
		rf_w128(rambox + pos, 14, pat2, pat3);
	}
}

static inline void rfv2_div_mod(ulong *p, ulong *q)
{
	ulong x = *p;
	*p = x / *q;
	*q = rf_revbit64(rf_revbit64(*q) + x);
}

static inline void rfv2_divbox(ulong *v0, ulong *v1)
{
	ulong pl, ql, ph, qh;

	//---- low word ----    ---- high word ----
	pl = ~*v0;              ph = ~*v1;
	ql = rf_bswap64(*v0);   qh = rf_bswap64(*v1);

	if (!pl || !ql)   { pl = ql = 0; }
	else if (pl > ql) rfv2_div_mod(&pl, &ql);
	else              rfv2_div_mod(&ql, &pl);

	if (!ph || !qh)   { ph = qh = 0; }
	else if (ph > qh) rfv2_div_mod(&ph, &qh);
	else              rfv2_div_mod(&qh, &ph);

	pl += qh;               ph += ql;
	*v0 -= pl;              *v1 -= ph;
}

static inline void rfv2_rotbox(ulong *v0, ulong *v1, uchar b0, uchar b1)
{
	ulong l, h;

	//---- low word ----         ---- high word ----
	l   = *v0;                   h  = *v1;
	l   = rf_rotr64(l, b0);      h  = rf_rotl64(h, b1);
	l  += rf_wltable(b0);        h += rf_whtable(b1);
	b0  = l;                     b1 = h;
	l   = rf_rotl64(l, b1);      h  = rf_rotr64(h, b0);
	b0  = l;                     b1 = h;
	l   = rf_rotr64(l, b1);      h  = rf_rotl64(h, b0);
	*v0 = l;                     *v1 = h;
}

static inline uint rfv2_scramble(rfv2_ctx_t *ctx)
{
	return ctx->crc = rf_crc32x4(ctx->hash.d, ctx->crc);
}

static inline void rfv2_inject(rfv2_ctx_t *ctx)
{
	ctx->crc = rf_crc32_32(rfv2_scramble(ctx), ctx->word);
	ctx->word = 0;
}

static inline void rfv2_rot32x256(hash256_t *hash)
{
	uint8 h0, h1;

	h0 = *(uint8 *)hash;
	h1.s0 = h0.s7;
	h1.s1 = h0.s0;
	h1.s2 = h0.s1;
	h1.s3 = h0.s2;
	h1.s4 = h0.s3;
	h1.s5 = h0.s4;
	h1.s6 = h0.s5;
	h1.s7 = h0.s6;
	*(uint8 *)hash = h1;
}

static inline void rfv2_aesenc(rfv2_ctx_t *ctx)
{
	aes2r_encrypt((uchar *)ctx->hash.b, (uchar *)ctx->hash.b + 16);
}

static inline void rfv2_one_round(rfv2_ctx_t *ctx)
{
	ulong carry;

	rfv2_rot32x256(&ctx->hash);

	carry = ((ulong)ctx->len << 32) + ctx->crc;
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, carry, carry >> 56);
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, carry >> 8, carry >> 48);
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, carry >> 16, carry >> 40);
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_scramble(ctx);

	carry = rfv2_rambox(ctx, carry);
	rfv2_rotbox(ctx->hash.q, ctx->hash.q + 1, carry >> 24, carry >> 32);
	rfv2_scramble(ctx);
	rfv2_divbox(ctx->hash.q, ctx->hash.q + 1);
	rfv2_inject(ctx);
	rfv2_aesenc(ctx);
	rfv2_scramble(ctx);
}

static void rfv2_init(rfv2_ctx_t *ctx, uint seed, __global void *rambox)
{
	*(uint8 *)ctx->hash.b = *(__constant const uint8 *)rfv2_iv;
	ctx->crc = seed;
	ctx->word = ctx->len = 0;
	ctx->changes = 0;
	ctx->rb_o = 0;
	ctx->rb_l = RFV2_RAMBOX_SIZE;
	ctx->rambox = (__global ulong *)rambox;
}

static void rfv2_update(rfv2_ctx_t *ctx, const void *msg, size_t len)
{
	const uchar *msg8 = (const uchar *)msg;

	while (len > 0) {
		if (!(ctx->len & 3) && len >= 4) {
			ctx->word = *(uint *)msg8;
			ctx->len += 4;
			rfv2_one_round(ctx);
			msg8 += 4;
			len -= 4;
			continue;
		}
		ctx->word |= ((uint)*msg8++) << (8 * (ctx->len++ & 3));
		len--;
		if (!(ctx->len & 3))
			rfv2_one_round(ctx);
	}
}

static inline void rfv2_pad256(rfv2_ctx_t *ctx)
{
	const uchar pad256[32] = { 0, };
	uint pad;

	pad = (32 - ctx->len) & 0xF;
	if (pad)
		rfv2_update(ctx, pad256, pad);
}

static void rfv2_final(void *out, rfv2_ctx_t *ctx)
{
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	rfv2_one_round(ctx);
	*(uint8 *)out = *(uint8 *)ctx->hash.b;
}

static uint sin_scaled(uint x)
{
	int i;

	i = ((x * 42722829) >> 24) - 128;
	x = 15 * i * i * abs(i);
	x = (x + (x >> 4)) >> 17;
	return 257 - x;
}

static int rfv2_hash2(void *out, const void *in, size_t len, __global void *rambox, __global const void *rambox_template, uint seed)
{
	rfv2_ctx_t ctx;
	uint loop, loops;
	uint msgh;

	//int alloc_rambox = (rambox == NULL);
	//
	//if (alloc_rambox) {
	//	rambox = malloc(RFV2_RAMBOX_SIZE * 8);
	//	if (rambox == NULL)
	//		return -1;
	//
	//	if (rambox_template)
	//		memcpy(rambox, rambox_template, RFV2_RAMBOX_SIZE * 8);
	//	else
	//		rfv2_raminit(rambox);
	//}

	//rfv2_ram_test(rambox);

	rfv2_init(&ctx, seed, rambox);
	msgh = rf_crc32_mem(0, in, len);
	ctx.rb_o = msgh % (ctx.rb_l / 2);
	ctx.rb_l = (ctx.rb_l / 2 - ctx.rb_o) * 2;

	loops = sin_scaled(msgh);
	if (loops >= 128)
		ctx.left_bits = 4;
	else if (loops >= 64)
		ctx.left_bits = 3;
	else if (loops >= 32)
		ctx.left_bits = 2;
	else if (loops >= 16)
		ctx.left_bits = 1;
	else
		ctx.left_bits = 0;
	for (loop = 0; loop < loops; loop++) {
		rfv2_update(&ctx, in, len);
		// pad to the next 256 bit boundary
		rfv2_pad256(&ctx);
	}

	rfv2_final(out, &ctx);

	//if (alloc_rambox)
	//	free(rambox);
	//else
	if (ctx.changes == RFV2_RAMBOX_HIST) {
		rfv2_raminit(rambox);
	}
	else if (ctx.changes > 0) {
		loops = ctx.changes;
		do {
			loops--;
			ctx.rambox[ctx.hist[loops]] = ctx.prev[loops];
		} while (loops);
	}
	return 0;
}

static int rfv2_hash(void *out, const void *in, size_t len, __global void *rambox, __global const void *rambox_template)
{
	return rfv2_hash2(out, in, len, rambox, rambox_template, RFV2_INIT_CRC);
}

// validate the reference hash
int check_hash(__global ulong *rambox)
{
	const uchar data[80] =
		"\x01\x02\x04\x08\x10\x20\x40\x80"
		"\x01\x03\x05\x09\x11\x21\x41\x81"
		"\x02\x02\x06\x0A\x12\x22\x42\x82"
		"\x05\x06\x04\x0C\x14\x24\x44\x84"
		"\x09\x0A\x0C\x08\x18\x28\x48\x88"
		"\x11\x12\x14\x18\x10\x30\x50\x90"
		"\x21\x22\x24\x28\x30\x20\x60\xA0"
		"\x41\x42\x44\x48\x50\x60\x40\xC0"
		"\x81\x82\x84\x88\x90\xA0\xC0\x80"
		"\x18\x24\x42\x81\x99\x66\x55\xAA";

	const uchar test_msg_out[32] =
		"\xe9\x46\xdf\xcd\x6b\x29\xc3\x9e"
		"\xb1\x07\xca\x71\xc4\x5f\xff\xf2"
		"\xf1\xeb\x47\x30\x5c\x60\x50\xa1"
		"\x7e\x4c\x5d\x3f\x0a\xd3\x32\xcb";

	uchar hash[32];
	int i;

	rfv2_hash(&hash, &data, sizeof(data), rambox, 0);

	for (i = 0; i < 32 && hash[i] == test_msg_out[i]; i++)
		;

	if (i == 32)
		return 1;

	printf("[%u] Invalid hash: test data:\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "   hash:\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
	       "     %02x %02x %02x %02x %02x %02x %02x %02x\n",
	       get_global_id(0),
	       data[0x00], data[0x01], data[0x02], data[0x03], data[0x04], data[0x05], data[0x06], data[0x07],
	       data[0x08], data[0x09], data[0x0a], data[0x0b], data[0x0c], data[0x0d], data[0x0e], data[0x0f],
	       data[0x10], data[0x11], data[0x12], data[0x13], data[0x14], data[0x15], data[0x16], data[0x17],
	       data[0x18], data[0x19], data[0x1a], data[0x1b], data[0x1c], data[0x1d], data[0x1e], data[0x1f],
	       data[0x20], data[0x21], data[0x22], data[0x23], data[0x24], data[0x25], data[0x26], data[0x27],
	       data[0x28], data[0x29], data[0x2a], data[0x2b], data[0x2c], data[0x2d], data[0x2e], data[0x2f],
	       data[0x30], data[0x31], data[0x32], data[0x33], data[0x34], data[0x35], data[0x36], data[0x37],
	       data[0x38], data[0x39], data[0x3a], data[0x3b], data[0x3c], data[0x3d], data[0x3e], data[0x3f],
	       data[0x40], data[0x41], data[0x42], data[0x43], data[0x44], data[0x45], data[0x46], data[0x47],
	       data[0x48], data[0x49], data[0x4a], data[0x4b], data[0x4c], data[0x4d], data[0x4e], data[0x4f],
	       hash[0x00], hash[0x01], hash[0x02], hash[0x03], hash[0x04], hash[0x05], hash[0x06], hash[0x07],
	       hash[0x08], hash[0x09], hash[0x0a], hash[0x0b], hash[0x0c], hash[0x0d], hash[0x0e], hash[0x0f],
	       hash[0x10], hash[0x11], hash[0x12], hash[0x13], hash[0x14], hash[0x15], hash[0x16], hash[0x17],
	       hash[0x18], hash[0x19], hash[0x1a], hash[0x1b], hash[0x1c], hash[0x1d], hash[0x1e], hash[0x1f]);
	return 0;
}

////////////////////////// equivalent of rfv2_cpuminer.c ////////////////////////

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)

// input:    clState->CLbuffer0    (80 bytes long)
// output:   clState->outputBuffer (32 bytes long)
// padcache: clState->padbuffer8   (96 MB / thread)

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const ulong *input, __global uint *output, __global ulong *padcache, const ulong target)
{
	uint gid = get_global_id(0);
	uchar data[80];
	rfv2_ctx_t ctx;
	uchar hash[32];
	__global ulong *rambox = padcache + (gid % MAX_GLOBAL_THREADS) * RFV2_RAMBOX_SIZE;

	// the rambox must be initialized by the first call for each thread
	if (gid < MAX_GLOBAL_THREADS) {
		// printf("init glob %u lt %u maxglob=%u\n", gid, get_local_id(0), MAX_GLOBAL_THREADS);
		rfv2_raminit(rambox);
		check_hash(rambox);
	}

	((uint16 *)data)[0] = ((__global const uint16 *)input)[0];
	((uint4 *)data)[4] = ((__global const uint4 *)input)[4];

	rfv2_hash(&hash, &data, 80, rambox, 0);

	if (0 && gid == 0/*0x123456*/) { // only for debugging
		printf("[%u] data:\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "   hash:\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n"
		       "     %02x %02x %02x %02x %02x %02x %02x %02x\n",
		       gid,
		       data[0x00], data[0x01], data[0x02], data[0x03], data[0x04], data[0x05], data[0x06], data[0x07],
		       data[0x08], data[0x09], data[0x0a], data[0x0b], data[0x0c], data[0x0d], data[0x0e], data[0x0f],
		       data[0x10], data[0x11], data[0x12], data[0x13], data[0x14], data[0x15], data[0x16], data[0x17],
		       data[0x18], data[0x19], data[0x1a], data[0x1b], data[0x1c], data[0x1d], data[0x1e], data[0x1f],
		       data[0x20], data[0x21], data[0x22], data[0x23], data[0x24], data[0x25], data[0x26], data[0x27],
		       data[0x28], data[0x29], data[0x2a], data[0x2b], data[0x2c], data[0x2d], data[0x2e], data[0x2f],
		       data[0x30], data[0x31], data[0x32], data[0x33], data[0x34], data[0x35], data[0x36], data[0x37],
		       data[0x38], data[0x39], data[0x3a], data[0x3b], data[0x3c], data[0x3d], data[0x3e], data[0x3f],
		       data[0x40], data[0x41], data[0x42], data[0x43], data[0x44], data[0x45], data[0x46], data[0x47],
		       data[0x48], data[0x49], data[0x4a], data[0x4b], ((uchar *)&gid)[0], ((uchar *)&gid)[1], ((uchar *)&gid)[2], ((uchar *)&gid)[3],

		       hash[0x00], hash[0x01], hash[0x02], hash[0x03], hash[0x04], hash[0x05], hash[0x06], hash[0x07],
		       hash[0x08], hash[0x09], hash[0x0a], hash[0x0b], hash[0x0c], hash[0x0d], hash[0x0e], hash[0x0f],
		       hash[0x10], hash[0x11], hash[0x12], hash[0x13], hash[0x14], hash[0x15], hash[0x16], hash[0x17],
		       hash[0x18], hash[0x19], hash[0x1a], hash[0x1b], hash[0x1c], hash[0x1d], hash[0x1e], hash[0x1f]);
	}

	barrier(CLK_LOCAL_MEM_FENCE);

	bool result = (((ulong*)hash)[3] <= target);
	if (result) {
		output[atomic_inc(output + 0xFF)] = SWAP4(gid);
	}
}

#endif // RAINFOREST_CL
