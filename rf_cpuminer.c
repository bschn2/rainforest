// RainForest hash algorithm - cpuminer integration code
// Author: Bill Schneider
// Date: Feb 13th, 2018
//
// Build instructions on Ubuntu 16.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.

#include <miner.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "rf_core.c"

int scanhash_rf256(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t RF_ALIGN(64) hash[8];
	uint32_t RF_ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	rf256_ctx_t ctx, ctx_common;

	if (opt_benchmark)
		ptarget[7] = 0x0cff;

	//printf("thd%d work=%p htarg=%08x ptarg7=%08x first_nonce=%08x max_nonce=%08x hashes_done=%Lu\n",
	//       thr_id, work, Htarg, ptarget[7], first_nonce, max_nonce, (unsigned long)*hashes_done);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	// pre-compute the hash state based on the constant part of the header
	rf256_init(&ctx_common);
	rf256_update(&ctx_common, endiandata, 76);
	ctx_common.changes = 0;

	memcpy(&ctx, &ctx_common, sizeof(ctx));

	do {
		be32enc(&endiandata[19], nonce);
#ifndef RF_DISABLE_CTX_MEMCPY
#ifndef RF_DISABLE_CTX_HISTORY
		if (ctx.changes == RAMBOX_HIST)
			memcpy(&ctx, &ctx_common, sizeof(ctx));
		else {
			for (unsigned int i = 0; i < ctx.changes; i++) {
				unsigned int k = ctx.hist[i];
				ctx.rambox[k] = ctx_common.rambox[k];
			}
			memcpy(&ctx, &ctx_common, offsetof(rf256_ctx_t, hist));
		}
#else
		memcpy(&ctx, &ctx_common, sizeof(ctx));
#endif
		rf256_update(&ctx, endiandata+19, 4);
		if (ctx.hash.w[7])
			goto next;
		rf256_final(hash, &ctx);
#else
		rf256_hash(hash, endiandata, 80);
#endif

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
	next:
		nonce++;
	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
