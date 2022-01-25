#include "integrity.h"
#include <limits.h>
#include <inttypes.h>
#include <openssl/objects.h>
#include <omp.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef POR_MMAP
#include <sys/mman.h>
#endif

/*****Compile with -lm flag due to inclusion of math.h*****/
/***Compile using Makefile due to Mersenne Twist library***/
/***Compile with -lssl -lcrypto due to merkle.h***/

#define DEFAULT_DIGEST ("sha512-224")
#define DEFAULT_BLOCKSIZE (2 << 12)

int main(int argc, char* argv[]) {
	struct timespec timer;

	// arguments checks
	if (argc < 6) {
		printf("USAGE: %s <input_data> "
			"<output_client_config> "
			"<output_server_config> "
			"<output_merkle_config> "
			"<output_merkle_tree>\n",
			argv[0]);
		return 1;
	}

	FILE* fin, * fclient, * fserver, * fmerkle, * ftree;

	// input file must exist
	if ((fin = fopen(argv[1], "r")) == NULL) {
		printf("Input data file <%s> does not exist\n", argv[1]);
		return 2;
	}
	// output files will be overwritten, if they exist
	fclient = fopen(argv[2], "w");
	fserver = fopen(argv[3], "w");
	fmerkle = fopen(argv[4], "w");
	ftree   = fopen(argv[5], "w");

	// get file size
	struct stat s;
	stat(argv[1], &s);
	off_t fileSize = s.st_size;
	printf("The size of <%s> is %"PRIu64".\n", argv[1], fileSize);
    fflush(stdout);

	// calculate dimensions of matrix and write then to both configs
	// n: number of columns
	// m: number of rows
	// Both will be the same to begin
	uint64_t num_chunks = 1 + (fileSize - 1) / BYTES_UNDER_P;
	uint64_t n = ceil(sqrt((double)num_chunks) / CHUNK_ALIGN) * CHUNK_ALIGN;
	uint64_t m = 1 + (num_chunks - 1) / n;
	printf("Using m = %"PRIu64", n = %"PRIu64".\n", m, n);
    fflush(stdout);
	fwrite(&n, sizeof(uint64_t), 1, fclient);
	fwrite(&m, sizeof(uint64_t), 1, fclient);
	fwrite(&n, sizeof(uint64_t), 1, fserver);
	fwrite(&m, sizeof(uint64_t), 1, fserver);

	// write data file name to fserver
	char actualPath[PATH_MAX];
	char* trash = realpath(argv[1], actualPath);
	if (trash == NULL) {
		fprintf(stderr, "ERROR: realpath returned null\n");
		exit(1);
	}
	int pathSize = 1; //account for null byte now
	while (*trash++) pathSize++;
	fwrite(&pathSize, sizeof(pathSize), 1, fserver);
	fwrite(actualPath, 1, pathSize, fserver);
	printf("Wrote <%s> of size of %d\n", actualPath, pathSize);
    fflush(stdout);

	// create random vector of size m and write to client config
	// using Tiny Mersenne Twister as pseudo-random number generator
	uint64_t* vector1 = calloc(m, sizeof *vector1);
	uint64_t seed = (uint64_t)2020;
	tinymt64_t state = {0};
	tinymt64_init(&state, seed);

	for (int i = 0; i < m; i++) { /*random1*/
		vector1[i] = rand_mod_p(&state);
		//fwrite(&vector1[i], sizeof(uint64_t), 1, fclient);
	}
	fwrite(vector1, sizeof *vector1, m, fclient);
	printf("Random vectors appended to %s.\n", argv[2]);
    fflush(stdout);

	start_time(&timer);

	// perform matrix mult and store in output file
	// this only runs through the input once (only stores n values at a time,
	// updating along the way for each row)
	// also appends input to server config along the way
	uint128_t* partials1 = calloc(n, sizeof *partials1);
	printf("Reading from <%s>...\n", argv[1]);
    fflush(stdout);

	uint64_t bytes_per_row = BYTES_UNDER_P * n;
	assert (n % 8 == 0);
	static const uint64_t CHUNK_MASK = (UINT64_C(1) << (8 * BYTES_UNDER_P)) - 1;

#pragma omp parallel reduction(+:partials1[:n])
	{
		printf("thread %d starting vector-matrix mul\n", omp_get_thread_num());
		size_t accum_count = 0;
		int fd = open(argv[1], O_RDONLY);
		assert (fd >= 0);
#ifdef POR_MMAP
		void *fdmap = mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
		assert (fdmap != MAP_FAILED);
		close(fd);
#else // no MMAP
		uint64_t *raw_row = malloc(bytes_per_row);
		assert (raw_row);
#endif // POR_MMAP

#pragma omp for schedule(static) nowait
		for (size_t i = 0; i < m; i++) {
			// mod reduce in case of overflow
			if (++accum_count > MAX_ACCUM_P) {
				for (size_t k = 0; k < n; ++k) {
					partials1[k] %= P57;
				}
				accum_count = 1;
			}

#ifdef POR_MMAP
			// get a pointer to the row
			uint64_t *raw_row;
			if (i < m-1) {
				raw_row = fdmap + (bytes_per_row * i);
			}
			else {
				raw_row = calloc(bytes_per_row, 1);
				memcpy(raw_row, fdmap + (bytes_per_row * i), fileSize - (bytes_per_row * i));
			}
#else // no MMAP
			my_pread(fd, raw_row, bytes_per_row, bytes_per_row * i);
#endif // POR_MMAP

			// XXX: this part assumes BYTES_UNDER_P equals 7
			assert (BYTES_UNDER_P == 7);
			// accumulate across one row, 56 bytes (8 chunks) at a time
			for (size_t raw_ind = 0, full_ind = 0; full_ind < n; raw_ind += 7, full_ind += 8) {
				uint128_t data_val = raw_row[raw_ind] & CHUNK_MASK;
				partials1[full_ind] += data_val * vector1[i];

				for (int k = 1; k < 7; ++k) {
					data_val = (raw_row[raw_ind + k - 1] >> (64 - k*8))
						| ((raw_row[raw_ind + k] << (k*8)) & CHUNK_MASK);
					partials1[full_ind + k] += data_val * vector1[i];
				}

				data_val = raw_row[raw_ind + 6] >> 8;
				partials1[full_ind + 7] += data_val * vector1[i];
			}
			// XXX (end assumption that BYTES_UNDER_P equals 7)

#ifdef POR_MMAP
			if (i == m-1) {
				free(raw_row);
			}
#endif // POR_MMAP
		}

#ifdef POR_MMAP
		munmap(fdmap, fileSize);
#else // no MMAP
		free(raw_row);
		close(fd);
#endif // POR_MMAP

		// mod reduction before parallel accumulate
		for (size_t k = 0; k < n; ++k) {
			partials1[k] %= P57;
		}
		printf("thread %d finished vector-matrix mul\n", omp_get_thread_num());
	}

    fflush(stdout);
	free(vector1);

	// final mod reduction after parallel accumulate
	for (size_t k = 0; k < n; ++k) {
		partials1[k] %= P57;
	}

	double mul_time = stop_time(&timer);
	printf("vector-matrix mul took %lg seconds\n", mul_time);
    fflush(stdout);

	// write sums (secret vectors) to the client config
	uint64_t *secret1 = malloc(n * sizeof *secret1);
	for (size_t i = 0; i < n; ++i) {
		assert (partials1[i] < P57);
		secret1[i] = partials1[i];
	}
	free(partials1);
	fwrite(secret1, sizeof *secret1, n, fclient);
	free(secret1);

	/*printf("\n");*/
	printf("Secret vectors appended to <%s>.\n", argv[2]);
	fclose(fclient);
	fclose(fserver);
  printf("Client config <%s> completed.\nServer config <%s> completed.\n",
	argv[2], argv[3]);
    fflush(stdout);

	start_time(&timer);
	 // initiate merkle tree structure
	 store_info_t merkleinfo;
	 work_space_t wspace;

	 merkleinfo.hash_nid = OBJ_txt2nid(DEFAULT_DIGEST);
	 merkleinfo.block_size = DEFAULT_BLOCKSIZE;
	 merkleinfo.size = fileSize;
	 
	 store_info_fillin(&merkleinfo);
	 init_work_space(&merkleinfo, &wspace);

	 // create merkle tree over data - stored in ftree
	 init_root(fin, ftree, &merkleinfo, &wspace);
	 fclose(fin);

	 // store details in merkle config
	 store_info_store(fmerkle, true, &merkleinfo);

	double merkle_time = stop_time(&timer);
	printf("merkle took %lg seconds\n", merkle_time);


	// cleanup
	 fclose(fmerkle);
	 fclose(ftree);
	 clear_work_space(&wspace);

	/*fserver = fopen(argv[3], "r");*/
	/*uint64_t test;*/
	/*for (int i = 0; i < (n*n)+2; i++) {*/
		/*fread(&test, sizeof(uint64_t), 1, fserver);*/
		/*printf("ServerConfig: "PRIu64"\n", test);*/
	/*}*/
	/*fclose(fserver);*/

	// Everything actually worked
	return 0;
}
