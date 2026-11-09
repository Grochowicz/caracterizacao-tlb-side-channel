#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define PAGE_SIZE 4096
#define MAX_MAP_SIZE (512UL * 1024UL * 1024UL)
#define MAX_RANDOM_ENTRIES (16UL * 1024UL * 1024UL)

#define FREQ 5.4

static int test_hugepage = 0;
static int random_list = 0;
static void *map_base = NULL;
static size_t map_allocation_size = 0;

static void die(const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	fprintf(stderr, "test-tlb(pid=%ld): ", (long)getpid());
	vfprintf(stderr, fmt, argp);
	va_end(argp);
	fputc('\n', stderr);
	exit(1);
}

static volatile int stop = 0;
static volatile sig_atomic_t terminate_requested = 0;

static void alarm_handler(int sig)
{
	(void)sig;
	stop = 1;
}

static void terminate_handler(int sig)
{
	(void)sig;
	terminate_requested = 1;
	stop = 1;
}

unsigned long usec_diff(struct timeval *a, struct timeval *b)
{
	unsigned long usec;

	usec = (b->tv_sec - a->tv_sec)*1000000;
	usec += b->tv_usec - a->tv_usec;
	return usec;
}

/*
 * Warmup run.
 *
 * This is mainly to make sure that we can go around the
 * map without timing any writeback activity from the cache
 * from creating the map.
 */
static unsigned long warmup(void *map)
{
	unsigned int offset = 0;
	struct timeval start, end;

	gettimeofday(&start, NULL);
	do {
		offset = *(volatile unsigned int *)(map + offset);
	} while (offset);
	gettimeofday(&end, NULL);
	return usec_diff(&start, &end);
}

static double do_test(void *map)
{
	unsigned long count = 0, offset = 0, usec;
	struct timeval start, end;
	struct itimerval itval =  {
		.it_interval = { 0, 0 },
		.it_value = { 0, 0 },
	};

	/*
	 * Do one run without counting, and make sure we can do
	 * at least five runs, and have at least about 0.2s of
	 * timing granularity (0.2s selected randomly to make the
	 * run-of-five take 1s in the fast case).
	 */
	usec = warmup(map) * 5;
	if (usec < 200000)
		usec = 200000;
	itval.it_value.tv_sec = usec / 1000000;
	itval.it_value.tv_usec = usec % 1000000;

	stop = 0;
	signal(SIGALRM, alarm_handler);
	setitimer(ITIMER_REAL, &itval, NULL);

	gettimeofday(&start, NULL);
	do {
		count++;
		offset = *(unsigned int *)(map + offset);
	} while (!stop);
	gettimeofday(&end, NULL);
	usec = usec_diff(&start, &end);
	if (count == 0)
		return 0;

	// Make sure the compiler doesn't compile away offset
	*(volatile unsigned int *)(map + offset);

	// return cycle time in ns
	return 1000 * (double) usec / count;
}

static unsigned long get_num(const char *str)
{
	char *end;
	unsigned long val, multiplier = 1;
	int saved_errno;

	if (!str)
		return 0;

	errno = 0;
	val = strtoul(str, &end, 0);
	saved_errno = errno;
	if (saved_errno == ERANGE || end == str || !val)
		return 0;

	if (*end != '\0') {
		switch (*end++) {
		case 'k':
			multiplier = 1UL << 10;
			break;
		case 'M':
			multiplier = 1UL << 20;
			break;
		case 'G':
			multiplier = 1UL << 30;
			break;
		default:
			return 0;
		}
		if (*end != '\0' || val > ULONG_MAX / multiplier)
			return 0;
	}

	return val * multiplier;
}

static void randomize_map(void *map, unsigned long size, unsigned long stride)
{
	unsigned long count = size / stride;
	uint32_t *rnd;

	if (count == 0 || count > MAX_RANDOM_ENTRIES ||
	    count > UINT32_MAX / stride)
		die("randomization requires too many entries: %lu", count);

	if (count > SIZE_MAX / sizeof(*rnd))
		die("randomization allocation size overflow");

	rnd = calloc(count, sizeof(*rnd));
	if (!rnd)
		die("out of memory");

	/* Create sorted list of offsets */
	for (unsigned long n = 0; n < count; n++)
		rnd[n] = (uint32_t)(n * stride);

	/* Fisher-Yates shuffle */
	for (unsigned long n = count - 1; n > 0; n--) {
		unsigned long m = (unsigned long)random() % (n + 1);
		uint32_t tmp = rnd[n];
		rnd[n] = rnd[m];
		rnd[m] = tmp;
	}

	/* Create a circular list from the random offsets */
	for (unsigned long n = 0; n < count; n++) {
		uint32_t *lastpos = (uint32_t *)((char *)map + rnd[n]);
		*lastpos = rnd[(n + 1) % count];
	}

	free(rnd);
}

// Hugepage size
#define HUGEPAGE (2*1024*1024)

static void *create_map(void *map, unsigned long size, unsigned long stride)
{
	unsigned int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	unsigned long off, mapsize;
	unsigned int *lastpos;

	/*
	 * If we're using hugepages, we will just re-use any existing
	 * hugepage map - the issues with different physical page
	 * allocations for cache associativity testing just isn't worth
	 * it with large pages.
	 *
	 * With regular pages, just mmap over the old allocation to
	 * force new page allocations. Hopefully this will then make
	 * the virtual mapping different enough to matter for timings.
	 */
	if (map && test_hugepage)
		return map;

	if (map && munmap(map, size) != 0)
		die("munmap failed: %s", strerror(errno));

	mapsize = size;
	if (test_hugepage)
		mapsize += 2*HUGEPAGE;

	map_base = mmap(NULL, mapsize, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (map_base == MAP_FAILED)
		die("mmap failed for %lu bytes: %s", mapsize, strerror(errno));
	map_allocation_size = mapsize;
	map = map_base;

	if (test_hugepage) {
		unsigned long mapstart = (unsigned long) map;
		mapstart += HUGEPAGE-1;
		mapstart &= ~(HUGEPAGE-1);
		map = (void *)mapstart;

		mapsize = size + HUGEPAGE-1;
		mapsize &= ~(HUGEPAGE-1);

		madvise(map, mapsize, MADV_HUGEPAGE);
	} else {
		/*
		 * Christian Borntraeger tested on an s390, and had
		 * transparent hugepages set to "always", which meant
		 * that the small-page case never triggered at all
		 * unless you explicitly ask for it.
		 */
		madvise(map, mapsize, MADV_NOHUGEPAGE);
	}

	lastpos = map;
	for (off = 0; off < size; off += stride) {
		lastpos = (unsigned int *)((char *)map + off);
		*lastpos = off + stride;
	}
	*lastpos = 0;

	return map;
}

int main(int argc, char **argv)
{
	unsigned long stride, size;
	const char *arg;
	void *map;
	double cycles;

	(void)argc;
	srandom(time(NULL));

	while ((arg = argv[1]) != NULL) {
		if (*arg != '-')
			break;
		for (;;) {
			switch (*++arg) {
			case 0:
				break;
			case 'H':
				test_hugepage = 1;
				continue;
			case 'r':
				random_list = 1;
				continue;
			default:
				die("Unknown flag '%s'", arg);
			}
			break;
		}
		argv++;
	}

	size = get_num(argv[1]);
	stride = get_num(argv[2]);
	if (stride < sizeof(uint32_t) || size < stride ||
	    size > MAX_MAP_SIZE || size % stride != 0 ||
	    stride > UINT32_MAX || size > UINT32_MAX)
		die("bad arguments: test-tlb [-H] <size> <stride>");

	struct timeval start, end;
	signal(SIGINT, terminate_handler);
	signal(SIGTERM, terminate_handler);
	gettimeofday(&start, NULL);
	map = NULL;
	while (!terminate_requested) {
		cycles = 1e10;
		for (int i = 0; i < 1; i++) {
			double d;

			map = create_map(map, size, stride);
			if (random_list)
				randomize_map(map, size, stride);
			if (terminate_requested)
				break;

			d = do_test(map);
			if (d > 0 && d < cycles)
				cycles = d;
		}
		if (terminate_requested)
			break;
		gettimeofday(&end, NULL);
		unsigned long elapsed_time = usec_diff(&start, &end);
		double timestamp = end.tv_sec + end.tv_usec / 1000000.0;
		printf("timestamp = %.6f, ", timestamp);
		printf("elapsed time = %ld ms, ", elapsed_time / 1000);
		printf("measured latency = %6.2fns (~%.1f cycles)\n", cycles, cycles*FREQ);
		fflush(stdout);

		/*
		./test-tlb -r 67108864 4096

		printf("size = %ld, stride = %ld, random_list = %d\n",size,stride, random_list);
		//alterna stride entre 64 e 4096
		stride ^= 4160;
		//alterna size entre 64k e 64M
		size ^= 67174400;
		*/
	}

	if (map && !test_hugepage) {
		if (munmap(map_base, map_allocation_size) != 0)
			die("munmap failed during shutdown: %s", strerror(errno));
	} else if (map && test_hugepage) {
		if (munmap(map_base, map_allocation_size) != 0)
			die("munmap hugepage area failed: %s", strerror(errno));
	}

	return 0;
}
