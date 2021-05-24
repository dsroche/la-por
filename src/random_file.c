// Random file generation
// first arg is output file
// second arg is size spec

#include "integrity.h"
#include <sys/random.h>
#include <getopt.h>
#include <fcntl.h>
#include <omp.h>

#define ROW_SIZE_BYTES (4194304) // 4MB

void usage(const char* arg0) {
	fprintf(stderr, "usage: %s [OPTIONS] <output_datafile> <size_spec>\n"
			"	-s --seed <number>		specify random seed\n"
			"	-h --help			show this help menu\n"
                        "<size_spec> should be a positive integer, followed optionally by one of\n"
                        "  K: KB (10^3 bytes)\n"
                        "  K: MB (10^6 bytes)\n"
                        "  K: MB (10^6 bytes)\n"
                        "  G: GB (10^9 bytes)\n"
                        "  T: TB (10^12 bytes)\n"
			, arg0);
}

int main(int argc, char* argv[]) {
	int datafd;
	uint64_t nbytes;

	int seeded = 0;
	uint64_t seed;

	// handle command line arguments
	struct option longopts[] = {
		{"seed", required_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (true) {
		switch (getopt_long(argc, argv, "s:h", longopts, NULL)) {
			case -1:
				goto done_opts;

			case 's':
				seed = strtoul(optarg, NULL, 10);
				seeded = 1;
				break;

			case 'h':
				usage(argv[0]);
				exit(1);

			default:
				fprintf(stderr, "unexpected getopt return value\n");
				exit(2);
		}
	}

done_opts:

	// read options from command line
	if (optind != argc - 2) {
		usage(argv[0]);
		exit(1);
	}

	const char* fname = argv[optind];
	if ((datafd = open(fname, O_WRONLY|O_CREAT, 0644)) < 0) {
		perror("could not open output file");
		return 2;
	}

	{
		const char* convstr = argv[optind+1];
		char* end;
		nbytes = strtoul(argv[optind+1], &end, 10);
		if (end == convstr || !(*end == '\0' || *(end+1) == '\0')) {
			fprintf(stderr, "invalid size specification '%s'n", convstr);
			return 2;
		}
		switch (*end) {
			case '\0':
				break;
			case 'k': case 'K':
				nbytes *= 1000ul;
				break;
			case 'm': case 'M':
				nbytes *= 1000000ul;
				break;
			case 'g': case 'G':
				nbytes *= 1000000000ul;
				break;
			case 't': case 'T':
				nbytes *= 1000000000000ul;
				break;
			default:
				fprintf(stderr, "invalid size specification '%s'\n", convstr);
				return 2;
		}
	}

	fprintf(stderr, "setting file length with ftruncate...");
	if (ftruncate(datafd, nbytes)) {
		perror("could not set file length as specified");
		return 2;
	}
	fprintf(stderr, "done\n");

	// seed RNG
	if (! seeded) {
#if __APPLE__
		if (getentropy(&seed, sizeof seed) == -1) {
			fprintf(stderr, "getentropy failed\n");
			exit(6);
		}
#else
		if (getrandom(&seed, sizeof seed, 0) != sizeof(seed)) {
			fprintf(stderr, "getrandom failed\n");
			exit(7);
		}
#endif
	}

	uint64_t nrows = 1 + (nbytes - 1) / ROW_SIZE_BYTES;
	const static uint64_t ROW_SIZE_64 = ROW_SIZE_BYTES / 8;

#pragma omp parallel
	{
		fprintf(stderr, "thread %d starting parallel writes\n", omp_get_thread_num());
		uint64_t *raw_row = malloc(ROW_SIZE_BYTES);
		assert (raw_row);

#pragma omp for nowait
		for (uint64_t i = 0; i < nrows; ++i) {
			tinymt64_t state = {0};
			tinymt64_init(&state, seed + i);

			for (size_t j = 0; j < ROW_SIZE_64; ++j) {
				raw_row[j] = tinymt64_generate_uint64(&state);
			}

			uint64_t offset = i * ROW_SIZE_BYTES;
			if (i == nrows - 1) {
				my_pwrite(datafd, raw_row, nbytes - offset, offset);
			}
			else {
				my_pwrite(datafd, raw_row, ROW_SIZE_BYTES, offset);
			}
		}

		fprintf(stderr, "thread %d finished\n", omp_get_thread_num());
	}

	close(datafd);

	printf("successfully wrote %lu bytes to %s\n", nbytes, fname);

	return 0;
}
