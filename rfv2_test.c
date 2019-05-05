// RainForest hash algorithm - test code
// Author: Bill Schneider
// Date: Feb 13th, 2018
//
// Build instructions on Ubuntu 16.04 :
//   - on x86:   use gcc -march=native or -maes to enable AES-NI
//   - on ARMv8: use gcc -march=native or -march=armv8-a+crypto+crc to enable
//               CRC32 and AES extensions.
//
//   - build with gcc -pthread to enable multi-thread operations

#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#if defined(_REENTRANT)
#include <pthread.h>
#endif
#endif

#include "rfv2_core.c"

// only defined when built with -pthread
#if defined(_REENTRANT) && defined(PTHREAD_MUTEX_INITIALIZER)
#define MAXTHREADS 256
#else
#define MAXTHREADS 1
#endif

static volatile unsigned long hashes;
static struct timeval tv_start;
static unsigned int threads = 1;

/* test message */
const uint8_t test_msg[80] =
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

/* valid pattern for a single rounds of the test message */
const uint8_t test_msg_out[32] =
	"\xe9\x46\xdf\xcd\x6b\x29\xc3\x9e"
	"\xb1\x07\xca\x71\xc4\x5f\xff\xf2"
	"\xf1\xeb\x47\x30\x5c\x60\x50\xa1"
	"\x7e\x4c\x5d\x3f\x0a\xd3\x32\xcb";

/* valid pattern for 256 rounds of the test message */
const uint8_t test_msg_out256[32] =
	"\xe9\x19\x7e\x12\x74\xe2\x60\x28"
	"\xb7\x6e\x2c\xe7\xdf\x78\xd8\x09"
	"\xc0\xf3\xa2\x0e\x74\xcd\x6f\x6c"
	"\x02\x5d\x75\xc2\x2c\x45\x99\x60";

void *run_bench(void *rambox)
{
	unsigned int loops = 0;
	unsigned int i;
	uint8_t msg[80];
	uint8_t out[32];

	memcpy(msg, test_msg, sizeof(msg));

	while (1) {
		/* modify the message on each loop */
		for (i = 0; i < sizeof(msg) / sizeof(msg[0]); i++)
			msg[i] ^= loops;

		rfv2_hash(out, msg, sizeof(msg), rambox, NULL);

		/* the output is reinjected at the beginning of the
		 * message, before it is modified again.
		 */
		memcpy(msg, out, 32);
		loops++;
#if MAXTHREADS > 1
		__sync_fetch_and_add(&hashes, 1);
#else
		hashes++;
#endif
	}
	return NULL;
}

void report_bench(int sig)
{
	struct timeval tv_now;
	unsigned long work;
	long sec, usec;
	double elapsed;
	(void)sig;

	gettimeofday(&tv_now, NULL);
	work = hashes; hashes = 0;
	sec = tv_now.tv_sec   - tv_start.tv_sec;
	usec = tv_now.tv_usec - tv_start.tv_usec;
	tv_start = tv_now;

	if (usec < 0) {
		usec += 1000000;
		sec -= 1;
	}
	elapsed = (double)sec + usec / 1000000.0;
	printf("%lu hashes, %.3f sec, %u thread%s, %.3f H/s, %.3f H/s/thread\n",
	       work, elapsed, threads, threads>1?"s":"",
	       (double)work / elapsed,
	       (double)work / elapsed / (double)threads);

	signal(SIGALRM, report_bench);
	alarm(1);
}

static void print256(const uint8_t *b, const char *tag)
{
	uint8_t i;

	printf("%s: ",tag);
	for (i = 0; i < 32;i++)
		printf("%02x",b[i]);
	printf("\n");
}

void usage(const char *name, int ret)
{
	printf("usage: %s [options]*\n"
	       "Options :\n"
	       "  -h           : display this help\n"
	       "  -b           : benchmark mode\n"
	       "  -c           : validity check mode\n"
	       "  -m <text>    : hash this text\n"
	       "  -t <threads> : use this number of threads\n"
	       "\n", name);
	exit(ret);
}

int main(int argc, char **argv)
{
	unsigned int loops;
	const char *name;
	const char *text;
	enum {
		MODE_NONE = 0,
		MODE_BENCH,
		MODE_CHECK,
		MODE_MESSAGE,
	} mode;

	name = argv[0];
	argc--; argv++;
	mode = MODE_NONE;
	text = NULL;
	while (argc > 0) {
		if (!strcmp(*argv, "-b")) {
			mode = MODE_BENCH;
		}
		else if (!strcmp(*argv, "-c")) {
			mode = MODE_CHECK;
		}
		else if (!strcmp(*argv, "-m")) {
			mode = MODE_MESSAGE;
			if (!--argc)
				usage(name, 1);
			text = *++argv;
		}
		else if (!strcmp(*argv, "-t")) {
			if (!--argc)
				usage(name, 1);
			threads = atoi(*++argv);
			if (threads < 1 || threads > MAXTHREADS) {
				printf("Fatal: threads must be between 1 and %u (was %u)\n",
				       MAXTHREADS, threads);
				exit(1);
			}
		}
		else if (!strcmp(*argv, "-h"))
			usage(name, 0);
		else
			usage(name, 1);
		argc--; argv++;
	}

	if (mode == MODE_NONE)
		usage(name, 1);

	if (mode == MODE_MESSAGE) {
		uint8_t out[32];

		rfv2_hash(out, text, strlen(text), NULL, NULL);
		print256(out, "out");
		exit(0);
	}

	if (mode == MODE_CHECK) {
		uint8_t msg[80];
		uint8_t out[32];
		void *rambox;

		rambox = malloc(RFV2_RAMBOX_SIZE * 8);
		if (rambox == NULL)
			exit(1);
		rfv2_raminit(rambox);

		/* preinitialize the message with a complex pattern that
		 * is easy to recognize.
		 */
		memcpy(msg, test_msg, sizeof(msg));

		printf("Single hash:\n");
		rfv2_hash(out, msg, sizeof(msg), rambox, NULL);
		if (memcmp(out, test_msg_out, sizeof(test_msg_out)) != 0) {
			print256(out, " invalid");
			print256(test_msg_out, "expected");
			exit(1);
		}
		print256(out, "valid");

		/* try the 256-loop pattern */
		printf("256-loop hash:\n");
		for (loops = 0; loops < 256; loops++) {
			unsigned int i;

			/* modify the message on each loop */
			for (i = 0; i < sizeof(msg) / sizeof(msg[0]); i++)
				msg[i] ^= loops;

			rfv2_hash(out, msg, sizeof(msg), rambox, NULL);

			/* the output is reinjected at the beginning of the
			 * message, before it is modified again.
			 */
			memcpy(msg, out, 32);
		}
		if (memcmp(out, test_msg_out256, sizeof(test_msg_out256)) != 0) {
			print256(out, " invalid");
			print256(test_msg_out256, "expected");
			exit(1);
		}
		print256(out, "valid");
		exit(0);
	}

	if (mode == MODE_BENCH) {
#if MAXTHREADS > 1
		pthread_t thread[MAXTHREADS];
#endif
		void *rambox[MAXTHREADS] = { NULL, };
		unsigned int thr;

		for (thr = 0; thr < threads; thr++) {
			rambox[thr] = malloc(RFV2_RAMBOX_SIZE * 8);
			if (rambox[thr] == NULL) {
				printf("Failed to allocate memory for thread %u\n", thr);
				exit(1);
			}

			rfv2_raminit(rambox[thr]);
		}

		gettimeofday(&tv_start, NULL);

		signal(SIGALRM, report_bench);
		alarm(1);

#if MAXTHREADS > 1
		for (thr = 0; thr < threads; thr++) {
			if (pthread_create(&thread[thr], NULL,
			                   run_bench, rambox[thr]) != 0) {
				printf("Failed to start thread %u\n", thr);
				exit(1);
			}
		}
		for (thr = 0; thr < threads; thr++)
			pthread_join(thread[thr], NULL);
#else
		run_bench(rambox[0]);
#endif
		/* should never get here */
	}
	exit(0);
}
