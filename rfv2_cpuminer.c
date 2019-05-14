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

#include "rfv2_core.c"

int scanhash_rfv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t RF_ALIGN(64) hash[8];
	uint32_t RF_ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	uint32_t msgh, msgh_init;
	void *rambox;
	int ret = 0;

	if (opt_benchmark)
		Htarg = ptarget[7] = 0x1ffff;

	//printf("thd%d work=%p htarg=%08x ptarg7=%08x first_nonce=%08x max_nonce=%08x hashes_done=%Lu\n",
	//       thr_id, work, Htarg, ptarget[7], first_nonce, max_nonce, (unsigned long)*hashes_done);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	rambox = malloc(RFV2_RAMBOX_SIZE * 8);
	if (rambox == NULL)
		goto out;

	rfv2_raminit(rambox);
	// pre-compute the hash state based on the constant part of the header
	msgh_init = rf_crc32_mem(0, endiandata, 76);

	do {
		be32enc(&endiandata[19], nonce);
#ifndef RFV2_TRY_ALL_HASHES
		msgh = rf_crc32_mem(msgh_init, &endiandata[19], 4);
		if (sin_scaled(msgh) != 2)
			goto next;
#endif
		rfv2_hash(hash, endiandata, 80, rambox, NULL);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			ret = 1;
			goto out;
		}
	next:
		nonce++;
	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
out:
	free(rambox);
	return ret;
}
