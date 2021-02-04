// Random file generation
// first arg is output file
// second arg is size spec

#include "integrity.h"
#include <sys/random.h>
#include <getopt.h>

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
	FILE* dataout;
	size_t nbytes;

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
	if ((dataout = fopen(fname, "w")) == NULL) {
		fprintf(stderr, "Cannot open output data file '%s'\n", fname);
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

	tinymt64_t state;
	tinymt64_init(&state, seed);

	size_t remain = nbytes;
	while (remain >= sizeof(uint64_t)) {
		uint64_t val = tinymt64_generate_uint64(&state);
		fwrite(&val, sizeof val, 1, dataout);
		remain -= sizeof val;
	}
	if (remain) {
		uint64_t val = tinymt64_generate_uint64(&state);
		fwrite(&val, remain, 1, dataout);
	}

	fclose(dataout);

	printf("successfully wrote %lu bytes to %s\n", nbytes, fname);

	return 0;
}
