#include "integrity.h"
#include <limits.h>
#include <openssl/objects.h>

/*****Compile with -lm flag due to inclusion of math.h*****/
/***Compile using Makefile due to Mersenne Twist library***/
/***Compile with -lssl -lcrypto due to merkle.h***/

#define DEFAULT_DIGEST ("sha512-224")
#define DEFAULT_BLOCKSIZE (2 << 12)

int main(int argc, char* argv[]) {
	// arguments checks
	if (argc < 5) {
		printf("USAGE: ./client_init <input_data> "
					"<output_client_config> "
					"<output_merkle_config> "
					"<output_merkle_tree>\n");
		return 1;
	}

	FILE* fin, * fclient, * fmerkle, * ftree;

	// input file must exist
	if ((fin = fopen(argv[1], "r")) == NULL) {
		printf("Input data file <%s> does not exist\n", argv[1]);
		return 2;
	}
	// output files will be overwritten, if they exist
	fclient = fopen(argv[2], "w");
	fmerkle = fopen(argv[3], "w");
	ftree   = fopen(argv[4], "w");

	// get file size
	struct stat s;
	stat(argv[1], &s);
	off_t fileSize = s.st_size;
	printf("The size of <%s> is "_CHUNK_SPECIFIER".\n", argv[1], fileSize);

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
	rewind(fin);

	// store details in merkle config
	store_info_store(fmerkle, true, &merkleinfo);

	// calculate dimensions of matrix and write then to config
	// n: number of columns
	// m: number of rows
	// Both will be the same to begin
	uint64_t n = ceil(sqrt((double)fileSize/sizeof(uint64_t)));
	uint64_t m = n;
	printf("Using n = m = "_CHUNK_SPECIFIER".\n", n);
	fwrite(&n, sizeof(uint64_t), 1, fclient);
	fwrite(&m, sizeof(uint64_t), 1, fclient);


	// create 2 random vectors of size m each and write to client config
	// using Tiny Mersenne Twister as pseudo-random number generator
	uint64_t* vector1 = calloc(m, sizeof(uint64_t));
	uint64_t* vector2 = calloc(m, sizeof(uint64_t));
	uint64_t seed = (uint64_t)2020;
	tinymt64_t state;
	tinymt64_init(&state, seed);

	for (int i = 0; i < m; i++) { /*random1*/
		vector1[i] = tinymt64_generate_uint64(&state);
		fwrite(&vector1[i], sizeof(uint64_t), 1, fclient);
		//printf("Random1: %lu\t", vector1[i]);
	}
	for (int i = 0; i < m; i++) { /*random2*/
		vector2[i] = tinymt64_generate_uint64(&state);
		fwrite(&vector2[i], sizeof(uint64_t), 1, fclient);
		//printf("Random2: %lu\t", vector2[i]);
	}
	printf("Random vectors appended to %s.\n", argv[2]);


	// perform matrix mult and store in output file
	// this only runs through the input once (only stores n values at a time,
	// updating along the way for each row)
	// also appends input to server config along the way
	uint64_t cur = 0;
	uint64_t* partials1 = calloc(n, sizeof(uint64_t));
	uint64_t* partials2 = calloc(n, sizeof(uint64_t));
	printf("Reading from <%s>...\n", argv[1]);

	for (int i = 0; i < m; i++) {
		for (int k = 0; k < n; k++) {
			// if there is no value (i.e. squaring off the matrix), then add 0,
			// otherwise, add the value times the vector value
			if (fread(&cur, sizeof(uint64_t), 1, fin) != 1)
				cur = 0;
			//printf("Data: %lu\t", cur);
			partials1[k] += n_mulmod2_preinv(cur, vector1[i], PRIME_1, PREINV_PRIME_1);
			partials2[k] += n_mulmod2_preinv(cur, vector2[i], PRIME_2, PREINV_PRIME_2);
		}
	}
	// write sums (secret vectors) to the client config
	// only modulo after last addition
	for (int i = 0; i < n; i++) { /*secret1*/
		cur = partials1[i] % PRIME_1;
		fwrite(&cur, sizeof(uint64_t), 1, fclient);
		//printf("Secret1: %lu\t", cur);
	}
	for (int i = 0; i < n; i++) { /*secret2*/
		cur = partials2[i] % PRIME_2;
		fwrite(&cur, sizeof(uint64_t), 1, fclient);
		//printf("Secret2: %lu\t", cur);
	}
	printf("Secret vectors appended to <%s>.\n", argv[2]);

	// cleanup
	fclose(fin);
	fclose(fclient);
	fclose(fmerkle);
	fclose(ftree);
	clear_work_space(&wspace);
	printf("Client config <%s> completed.\n", argv[2]);


	// Everything actually worked
	return 0;
}

