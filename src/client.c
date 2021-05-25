// Client Side Script
// first arg is config file
// second arg is merkle config
// third arg is IP (or "localhost" or "gserver")
// fourth arg is port number to connect to

#include <sys/random.h>
#include <getopt.h>
#include <integrity.h>

#define MAX(a,b) ((a) < (b) ? (b) : (a))

void usage(const char* arg0) {
	fprintf(stderr, "usage: %s [OPTIONS] [<config_file>] [<merkle_config_file>]\n"
			"	-s --serverIP		IP address of the cloud server; defaults to 'localhost'\n"
			"	-p --port			port over which to connect with cloud server; defaults to 2020\n"
			"	-a --audit		run an audit (non-interatively)\n"
			"	-v --verbose		verbose mode\n"
			"	-h --help			show this help menu\n"
			, arg0);
}

void my_fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
void my_fwrite(void* ptr, size_t size, size_t nmemb, FILE* stream);
uint64_t* makeChallengeVector(uint64_t size); 
int runAudit(FILE* fconfig, uint64_t* challenge1,
				uint64_t* response1, uint64_t n, uint64_t m);

bool client_prep_read(read_req_t* rreq, char** buf, uint64_t* bufsize,
    const store_info_t* info, work_space_t* space);
bool client_post_read(read_req_t* rreq, const store_info_t* info, work_space_t* space);
void my_fread_rreq(read_req_t* rreq, uint64_t bufsize, FILE* sock, const store_info_t* info);

int main(int argc, char* argv[]) {
	int verbose = 0; /*defaults to off*/
	FILE* fconfig, * fmerkleconfig;
	uint64_t n, m;
	struct sockaddr_in addr;
	memset(&(addr), '\0', sizeof(addr));
	short port = 2020; /*defaults to port 2020*/
	struct timespec timer;
	double client_comp_time = 0;
	double comm_time = 0;
	int trash;
	int audit = 0;

	// handle command line arguments
	struct option longopts[] = {
		{"serverIP", required_argument, NULL, 's'},
		{"port", required_argument, NULL, 'p'},
		{"audit", no_argument, NULL, 'a'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (true) {
		switch (getopt_long(argc, argv, "s:p:avh", longopts, NULL)) {
			case -1:
				goto done_opts;

			case 's':
				if (strcmp(optarg, "localhost") == 0) {
					inet_aton("127.0.0.1", &addr.sin_addr);
				} else if ( sscanf(optarg, "%d.%d.%d.%d", &trash, &trash, &trash, &trash) != 4 ) {
					fprintf(stderr, "ERROR: invalid ip address\n");
					exit(1);
				} else {
					inet_aton(optarg, &addr.sin_addr);
				}
				break;

			case 'p':
				port = atoi(optarg);
				break;

			case 'a':
				audit = 1;
				break;

			case 'v':
				verbose = 1;
				break;

                        case 'h': case '?':
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
	if ((fconfig = fopen(argv[optind], "r+")) == NULL) {
		fprintf(stderr, "Config file <%s> does not exist\n", argv[1]);
		return 2;
	}
	if ((fmerkleconfig  = fopen(argv[optind+1], "r+")) == NULL) {
		fprintf(stderr, "Merkle Config file <%s> does not exist\n", argv[2]);
		return 3;
	}

	if (verbose) {
		printf("Verbose output requested\n");
	}

	// get dimensions n & m from config
	my_fread(&n, sizeof(uint64_t), 1, fconfig);
	my_fread(&m, sizeof(uint64_t), 1, fconfig);
	fprintf(stderr, "n="_CHUNK_SPECIFIER" and m="_CHUNK_SPECIFIER"\n", n, m);

	// load merkle context
	store_info_t sinfo;
	work_space_t wspace;
	read_req_t rreq;
	uint64_t bufsize = 1024;
	char* buf = malloc(bufsize);
	if (store_info_load(fmerkleconfig, true, &sinfo) <=0) {
		fprintf(stderr, "Improper Merkle config\n");
		return 4;
	}
	init_work_space(&sinfo, &wspace);
	update_signature(&sinfo, wspace.ctx);

	// open socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// connect to server
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);

	if( connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Connection on client side failed\n");
		return 5;
	}
	fprintf(stderr, "Connection made on client side\n");

	// convert socket to file
	FILE* sock = fdopen(sockfd, "r+");

	char op;
	if (audit) {
		op = '1';
	}
	else {
		// ask user for which operation
		printf("(1) Audit\n"
				"(2) Retrieve\n"
				"(3) Update\n"
				"Specify Operation: ");
		while (scanf(" %c", &op) != 1) {
			fprintf(stderr, "Operation not read\n");
		}
	}

	switch(op) {
		case '1':
			/* Audit */
			// send op code to server
			op = 'A';
			my_fwrite(&op, 1, 1, sock);
			fflush(sock);
			
			// create and send challenge vectors (of size n)
			start_time(&timer);				/* START COMP TIMER */
			uint64_t* challenge1;
			uint64_t challengeBytes = n * sizeof(uint64_t);
			challenge1 = makeChallengeVector(n);
			client_comp_time = stop_time(&timer);		/* PAUSE COMP TIMER */
			start_time(&timer);				/* START COMM TIMER */
			my_fwrite(challenge1, 1, challengeBytes, sock);
			fflush(sock);

			// wait for ACK from server
			char ack = '0';
			my_fread(&ack, 1, 1, sock);
			if (ack == '1') comm_time = stop_time(&timer);	/* STOP COMM TIMER */
			else printf("Did not receive ACK from server after sending challenge.\n");
			printf("challenge[0] = %"PRIu64"\n", challenge1[0]);
			printf("challenge[n-1] = %"PRIu64"\n", challenge1[n-1]);

			// read response vectors from server (of size m)
			uint64_t* response1 = calloc(m, sizeof(uint64_t));
			uint64_t responseBytes = m * sizeof(uint64_t);
			my_fread(response1, 1, responseBytes, sock);
			printf("response[0] = %"PRIu64"\n", response1[0]);
			printf("response[m-1] = %"PRIu64"\n", response1[m-1]);

			// send previous comm_time as ack to server
			my_fwrite(&comm_time, sizeof(comm_time), 1, sock);
			fflush(sock);
			fprintf(stderr, "Sent 1-way comm time of %f to server.\n", comm_time);

			// run audit and report to client
			// use m for size
			start_time(&timer);				/* RESUME COMP TIMER */
			int audit = runAudit(fconfig, challenge1,
							response1, n, m);
			client_comp_time += stop_time(&timer);		/* STOP TIMER */
			printf("Audit has ");
			printf(audit ? "PASSED!\n" : "FAILED.\n");

			//report computation time
			fprintf(stderr, "***CLIENT COMP TIME: %f***\n", client_comp_time);

			// clean up
			free(challenge1);
			free(response1);
			break;

		case '2':
			/*Retrieval*/
			// send op code to server
			op = 'R';
			my_fwrite(&op, 1, 1, sock);
			fflush(sock);

			// ask client for which chunk & check for valid limits
			if (!client_prep_read(&rreq, &buf, &bufsize, &sinfo, &wspace)) {
				fprintf(stderr, "Invalid request: Failed.\n");
			}

			// send info to get hashes
			my_fwrite(&rreq.nhash,        sizeof(uint32_t),          1, sock);
			fflush(sock);

			// get hashes from server
			for (uint32_t i = 0; i < rreq.nhash; i++) {
				my_fwrite(&rreq.hash_ind[i], sizeof(uint64_t), 1, sock);
				my_fread(&rreq.hashes[i], sinfo.hash_size, 1, sock);
			}

			// send info get blocks
			my_fwrite(&rreq.block_count,  sizeof(uint64_t),          1, sock);
			my_fwrite(&rreq.block_offset, sizeof(uint64_t),          1, sock);
			my_fwrite(&rreq.lbsize,       sizeof(uint32_t),          1, sock);
			fflush(sock);
			// read back blocks back
			if (rreq.block_count >= 2) {
				my_fread(rreq.first_block, sinfo.block_size, 1, sock);
			}
			if (rreq.block_count >= 3) {
				my_fread(rreq.middle_blocks, sinfo.block_size, rreq.block_count - 2, sock);
			}
			if (rreq.block_count >= 1) {
				my_fread(rreq.last_block, rreq.lbsize, 1, sock);
			}

			// check validity and present to client
			if (!client_post_read(&rreq, &sinfo, &wspace)) {
				fprintf(stderr, "Server's response is INVALID!\n");
			}

			free(buf);
			break;

		case '3':
			/*Update*/
			// send op code to server
			op = 'U';
			my_fwrite(&op, 1, 1, sock);
			fflush(sock);

			// ask client for which chunk
			printf("Which bytes [0-"_CHUNK_SPECIFIER"]? ", n*m*8-1);
			uint64_t initial;
			uint64_t final;
			if (scanf(""_CHUNK_SPECIFIER"-"_CHUNK_SPECIFIER"", &initial, &final) != 2) {
				fprintf(stderr, "Reading limits failed.\n");
			}
			assert(initial < n*m);
			assert(final < n*m);
			assert(initial <= final);

			// send first and last byte numbers to server
			my_fwrite(&initial, sizeof(uint64_t), 1, sock);
			my_fwrite(&final, sizeof(uint64_t), 1, sock);
			fflush(sock);

			// loop through updating each byte
			unsigned char newValue;
			uint64_t affectedRandom;
			uint64_t affectedSecret;
			uint64_t oldValue;
			uint64_t newVectorValue;
			uint64_t random1;
			uint64_t secret1;
			long index;
			unsigned char* oldByte = &newValue; /*initialized only to get rid of warning*/
			for (uint64_t i = initial; i <= final; i++) {

				// ask user for updated value
				printf("Updated value for byte "_CHUNK_SPECIFIER": ", i);
				while (scanf(" %c", &newValue) != 1) {
					fprintf(stderr, "Updated value not read properly.\n");
				}
				assert(newValue < 255);
				printf("Read from user: %#04x\n", newValue);
				/*printf("Updating...");*/

				// get old chunk value from server
				// when at last byte in chunk or initial
				if ( (i % sizeof(uint64_t)) == 0 || i == initial) {
					my_fread(&oldValue, sizeof(uint64_t), 1, sock);
					newVectorValue = oldValue;
					oldByte = (unsigned char*)&newVectorValue;

					// if this is initial
					// accouint for first not starting at beginning of chunk
					if (i == initial) oldByte += (initial % sizeof(uint64_t));
				}

				// send new value to server
				my_fwrite(&newValue, 1, 1, sock);
				fflush(sock);

				// update newVectorValue for this byte
				*oldByte = newValue;
				oldByte++;

				// if this is the last byte in a chunk,
				// update the secret vector
				if ( (i % sizeof(uint64_t)) == 7 || i == final) {
					// compute affected chunk indexes for secret vector
					affectedRandom = (i/sizeof(uint64_t)) / n;
					affectedSecret = (i/sizeof(uint64_t)) % n;
				
					// get corresponding values from random vectors
					fseek(fconfig, affectedRandom*sizeof(uint64_t), SEEK_CUR);
					my_fread(&random1, sizeof(uint64_t), 1, fconfig);

					// get corresponding values from secret vectors
					fseek(fconfig, (m - 1 - affectedRandom + affectedSecret)*sizeof(uint64_t), SEEK_CUR);
					index = ftell(fconfig); /*tag where to write later*/
					my_fread(&secret1, sizeof(uint64_t), 1, fconfig);
					
					// compute differences with updated value
					if (newVectorValue == oldValue) {
						printf("No update needed.\n");
						break;
					}else if (newVectorValue > oldValue) {
						secret1 = (uint64_t)((secret1 + ((uint128_t)(newVectorValue - oldValue)) * random1) % P57);
					}else {
						secret1 = (uint64_t)((secret1 + ((uint128_t)(newVectorValue + P57 - oldValue)) * random1) % P57);
					}


					// update the secret vectors at the affected index
					fseek(fconfig, index, SEEK_SET);
					my_fwrite(&secret1, sizeof(uint64_t), 1, fconfig);
					fflush(fconfig);

					// rewind the config file to after n,m
					fseek(fconfig, 2*sizeof(uint64_t), SEEK_SET);

					printf("Chunk "_CHUNK_SPECIFIER" updated.\n", affectedSecret);
				}
			}
			// report to client
			printf("Update Completed.\n");
			break;

		default:
			fprintf(stderr, "ERROR: Invalid mode given\n");
	}


	// clean up
	fclose(sock);
	fclose(fconfig);
	fclose(fmerkleconfig);
	close(sockfd);
	clear_work_space(&wspace);

	return 0;
}



void my_fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	int read = 0;
	if ((read = fread(ptr, size, nmemb, stream)) != nmemb) {
		fprintf(stderr, "ERROR: read %i instead of %li\n", read, nmemb);
		exit(1);
	}
}


void my_fwrite(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	if (fwrite(ptr, size, nmemb, stream) != nmemb) {
		fprintf(stderr, "ERROR: did not write proper amount\n");
		exit(1);
	}
}


uint64_t* makeChallengeVector(uint64_t size) {
	// seed Tiny Mersenne Twister
	uint64_t seed;
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
	tinymt64_t state = {0};
	tinymt64_init(&state, seed);

	// construct the randomized vector
	uint64_t* vector = calloc(size, sizeof(uint64_t));
	for (int i = 0; i < size; i++) {
		vector[i] = rand_mod_p(&state);
	}

	return vector;
}


int runAudit(FILE* fconfig, uint64_t* challenge1,
				uint64_t* response1, uint64_t n, uint64_t m) {
	uint128_t rxr1 = 0;
	uint128_t sxc1 = 0;

	// compute dot products:
	// random dot response & secret dot challenge.
	// config file read through once
	// doing modulo calc for each mul,
	// doing one modulo after all addition at end.
	size_t accum_count = 0;

	uint64_t *temp = malloc(MAX(m,n) * sizeof *temp);
	my_fread(temp, sizeof *temp, m, fconfig);

	for (int i = 0; i < m; i++) { /*random1 dot response1 (m)*/
		if ((accum_count += 2) > MAX_ACCUM_P) {
			rxr1 %= P57;
			accum_count = 2;
		}
		rxr1 += ((uint128_t)temp[i]) * response1[i];
	}
	rxr1 %= P57;
	accum_count = 0;
	my_fread(temp, sizeof *temp, n, fconfig);
	for (int i = 0; i < n; i++) { /*secret1 dot challenge1 (n)*/
		if ((accum_count += 2) > MAX_ACCUM_P) {
			sxc1 %= P57;
			accum_count = 2;
		}
		sxc1 += ((uint128_t)temp[i]) * challenge1[i];
	}
	sxc1 %= P57;
	free(temp);

	// check for equal and return result
	// 1 for pass
	// 0 for fail (default)
	printf("rxr1 = %"PRIu64"\n", (uint64_t)rxr1);
	printf("sxc1 = %"PRIu64"\n", (uint64_t)sxc1);
	return (rxr1 == sxc1);
}


bool client_prep_read(read_req_t* rreq, char** buf, uint64_t* bufsize,
    const store_info_t* info, work_space_t* space)
{
	uint64_t count, offset;

	if (scanf(" "_CHUNK_SPECIFIER" "_CHUNK_SPECIFIER"", &count, &offset) != 2) {
		fprintf(stderr, "ERROR: must specify count and offset for read op\n");
		return false;
	}

	if (offset > info->size) {
		fprintf(stderr, "ERROR: read offset "_CHUNK_SPECIFIER" exceeds size "_CHUNK_SPECIFIER"\n", offset, info->size);
		return false;
	}

	if (offset + count > info->size) {
		fprintf(stderr, "ERROR: read count goes past end of size\n");
		return false;
	}

	if (*bufsize < count) {
		*bufsize = MAX(2 * *bufsize, count);
		if (!(*buf = realloc(*buf, *bufsize))) {
		fprintf(stderr, "ERROR: can't allocate buffer large enough to read\n");
		exit(2);
		}
	}

	pre_read(rreq, *buf, count, offset, info, space);

	return true;
}

bool client_post_read(read_req_t* rreq, const store_info_t* info, work_space_t* space)
{
	if (post_read(rreq, info, space)) {
		printf("Root hash successfully validated! "_CHUNK_SPECIFIER" bytes follow next.\n", rreq->count);
		fwrite(rreq->buf, 1, rreq->count, stdout);
		printf("\n");
		fflush(stdout);
		return true;
	}
	else {
		fprintf(stderr, "ERROR: root hash computed from read did not validate!\n");
		return false;
	}
}
