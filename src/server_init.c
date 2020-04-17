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
		printf("USAGE: ./server_init <input_data> "
					"<output_server_config> "
					"<output_merkle_config> "
					"<output_merkle_tree>\n");
		return 1;
	}

	FILE* fin, * fserver, * fmerkle, * ftree;

	// input file must exist
	if ((fin = fopen(argv[1], "r")) == NULL) {
		printf("Input data file <%s> does not exist\n", argv[1]);
		return 2;
	}
	// output files will be overwritten, if they exist
	fserver = fopen(argv[2], "w");
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
	store_info_store(fmerkle, false, &merkleinfo);

	// calculate dimensions of matrix and write then to both configs
	// n: number of columns
	// m: number of rows
	// Both will be the same to begin
	uint64_t n = ceil(sqrt((double)fileSize/sizeof(uint64_t)));
	uint64_t m = n;
	printf("Using n = m = "_CHUNK_SPECIFIER".\n", n);
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


	// cleanup
	fclose(fin);
	fclose(fserver);
	fclose(fmerkle);
	fclose(ftree);
	clear_work_space(&wspace);
	printf("Server config <%s> completed.\n",
	argv[2]);


	// Everything actually worked
	return 0;
}

