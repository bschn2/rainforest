// RainForest hash algorithm - test code
// Author: Bill Schneider
// Date: Feb 13th, 2018
//
// Build instructions on Ubuntu 16.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.

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

static void print256(const uint8_t *b, const char *tag)
{
	printf("%s: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
	       ".%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       tag,
	       b[0],  b[1],  b[2],  b[3],  b[4],  b[5],  b[6],  b[7],
	       b[8],  b[9],  b[10], b[11], b[12], b[13], b[14], b[15],
	       b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
	       b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
}

int main(int argc, char **argv)
{
	unsigned int loops;
	uint32_t msg[20];
	unsigned char md[32];
	void *rambox;

	rambox = malloc(RF_RAMBOX_SIZE * 8);
	if (rambox == NULL)
		exit(1);
	rf_raminit(rambox);

	if (argc>1) {
		rf256_hash(md, (uint8_t*)argv[1], strlen(argv[1]), rambox);
		print256(md, "1step(argv1)   ");

		rf256_hash(md, (uint8_t*)argv[1], strlen(argv[1])+1, rambox);
		print256(md, "1step(argv1+\\0)");
		return 0;
	}

	for (loops=0;loops<20;loops++)
		msg[loops]=loops;

	for (loops=0; loops<10000/*00*/; loops++) {
		if (!(loops&0x3ffff))
			printf("%u\n", loops);
		msg[19] = loops;
		rf256_hash(md, msg, sizeof(msg), rambox);
		//memcpy(msg, md, 32);
	}
	printf("%u\n", loops);
	print256(md, "md");
	exit(0);
}
