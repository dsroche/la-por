// Cloud Server Script
// first arg is config file
// second arg is merkle file
// third arg is port number to listen on
#define POR_MMAP

#include "integrity.h"
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <omp.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef POR_MMAP
#include <sys/mman.h>
#endif

int server;
int clientfd;
FILE* client;
FILE* fconfig;
FILE* fmerkle;
FILE* dataMatrix;
work_space_t wspace;

void usage(const char* arg0) {
	fprintf(stderr, "usage: %s [OPTIONS] [<config_file>] [<merkle_config_file>]\n"
			"	-p --port			port over which to connect with cloud server; defaults to 2020\n"
			"	-v --verbose		verbose mode\n"
			"	-h --help			show this help menu\n"
			, arg0);
}

// Handler for SIGINT (Ctrl-C) and SIGTERM
void my_exits(void);

void handler(int signum);

void my_fread(void* ptr, size_t size, size_t nmemb, FILE* stream);
void my_fwrite(void* ptr, size_t size, size_t nmemb, FILE* stream);

uint64_t retrieveAndSend(uint64_t index, FILE* data, FILE* sock);

bool read_hash(uint64_t index, char* hash, FILE* merkle, const store_info_t* info);
bool send_blocks(uint64_t offset, uint64_t count, uint32_t lbsize, FILE* data, FILE* sock, const store_info_t* info);
void my_fwrite_rreq(read_req_t* rreq, uint64_t bufsize, FILE* sock, const store_info_t* info);


int main(int argc, char* argv[]) {

	short port = 2020; /*defaults to 2020*/
	int verbose = 0; /*defaults to off*/

	// register handler and make it run at exit as well
	signal(SIGINT, handler);
	signal(SIGTERM, handler);
	atexit(my_exits);

	// handle command line arguments
	struct option longopts[] = {
		{"port", required_argument, NULL, 'p'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (true) {
		switch (getopt_long(argc, argv, "p:vh", longopts, NULL)) {
			case -1:
				goto done_opts;

			case 'p':
				port = atoi(optarg);
				break;

			case 'v':
				verbose = 1;
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
	if ((fconfig = fopen(argv[optind], "r")) == NULL) {
		fprintf(stderr, "Config file <%s> does not exist\n", argv[1]);
		return 2;
	}
	if ((fmerkle  = fopen(argv[optind+1], "r")) == NULL) {
		fprintf(stderr, "Merkle Config file <%s> does not exist\n", argv[2]);
		return 3;
	}

	if (verbose) {
		printf("Verbose output requested\n");
	}

	// read in dimensions
	uint64_t n, m;
	my_fread(&n, sizeof(uint64_t), 1, fconfig);
	my_fread(&m, sizeof(uint64_t), 1, fconfig);

	// open data file
	int pathSize;
	my_fread(&pathSize, sizeof(int), 1, fconfig);
	printf("pathSize = %d\n", pathSize);
	char path[pathSize];
	my_fread(path, 1, pathSize, fconfig);
	printf("Going to open file <%s> of length %d\n", path, pathSize);
	dataMatrix = fopen(path, "r");

	// load Merkle context
	store_info_t sinfo;
	if (store_info_load(fmerkle, false, &sinfo) <= 0) {
		fprintf(stderr, "Cannot read Merkle header info\n");
		return 1;
	}
	init_work_space(&sinfo, &wspace);
	update_signature(&sinfo, wspace.ctx);

	// open TCP socket
	server = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }
    if (setsockopt(server, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0){
        perror("setsockopt(SO_REUSEPORT) failed");
    }


	// server address -- use port from user
	struct sockaddr_in host_addr, client_addr;
	memset(&(host_addr), '\0', sizeof(struct sockaddr_in));
	host_addr.sin_family=AF_INET;
	host_addr.sin_port=htons(port);
	host_addr.sin_addr.s_addr=INADDR_ANY;

   // bind server socket
	if( bind(server, (struct sockaddr*) &host_addr, sizeof(struct sockaddr)) < 0){
		perror("bind");
		return 1;
	}

	// start listening
	listen(server, 1);
	fprintf(stderr, "Listening...\n");

	// make the connection when it comes
	// after one connection is through, take the next
	socklen_t sin_size = sizeof(struct sockaddr_in);
	while( (clientfd = accept(server, (struct sockaddr*) &client_addr, &sin_size)) >= 0 ) {

		fprintf(stderr, "\nConnection made on server side\n");

		pid_t c_pid = fork();

		if (c_pid == 0) {

			client = fdopen(clientfd, "r+");
			fprintf(stderr, "\nTest Child\n");

			// read mode type from user
			// char 'A' (65) for audit
			// char 'R' (82) for retrieve
			// char 'U' (85) for update
			char mode;
			int gotem = read(clientfd, &mode, 1);
			assert (gotem == 1);
			fprintf(stderr, "\nTest Child\n");

			// perform operation
			switch (mode) {
				case 'A':
					/*audit stuff*/
					{
						fprintf(stderr, "Entering Audit Mode...\n");
#ifdef POR_MMAP
						fprintf(stderr, "using mmap for file reads\n");
#else // no MMAP
						fprintf(stderr, "using pread for file reads\n");
#endif // POR_MMAP

						uint64_t *challenge1 = malloc(n * sizeof *challenge1);
						uint64_t *dot_prods1 = malloc(m * sizeof *dot_prods1);

						my_fread(challenge1, sizeof *challenge1, n, client);
						char ack = '1';
						my_fwrite(&ack, 1, 1, client);
						fflush(client);

						fprintf(stderr, "Read %"PRIu64" bytes from client.\n", n * sizeof *challenge1);

						struct timespec timer, cpu_timer;
						start_time(&timer);
						start_cpu_time(&cpu_timer);

						struct timespec sread_cpu, sread_comp;
						double * sread_cpu_time = malloc(m * sizeof *sread_cpu_time);
						double * sread_comp_time = malloc(m * sizeof *sread_comp_time);
						struct stat s;
						stat(path, &s);
						uint64_t filenm = s.st_size;
						uint64_t bytes_per_row = BYTES_UNDER_P * n;
						assert (n % 8 == 0);
						static const uint64_t CHUNK_MASK = (UINT64_C(1) << (8 * BYTES_UNDER_P)) - 1;

#pragma omp parallel
						{
							fprintf(stderr, "thread %d starting matrix-vector mul\n", omp_get_thread_num());
							int fd = open(path, O_RDONLY);
							assert (fd >= 0);
#ifdef POR_MMAP
							void *fdmap = mmap(NULL, filenm, PROT_READ, MAP_PRIVATE, fd, 0);
							assert (fdmap != MAP_FAILED);
							close(fd);
#else // no MMAP
							uint64_t *raw_row = malloc(bytes_per_row);
							assert (raw_row);
#endif // POR_MMAP

#pragma omp for schedule(static) nowait
							for (size_t i = 0; i < m; ++i) {
								// get a pointer to the row
                            start_time(&sread_comp);
                            start_cpu_time(&sread_cpu);
#ifdef POR_MMAP
								uint64_t *raw_row;
								if (i < m-1) {
									raw_row = fdmap + (bytes_per_row * i);
								}
								else {
									raw_row = calloc(bytes_per_row, 1);
									memcpy(raw_row, fdmap + (bytes_per_row * i), filenm - (bytes_per_row * i));
								}
#else // no MMAP
								my_pread(fd, raw_row, bytes_per_row, bytes_per_row * i);
#endif // POR_MMAP
                            sread_comp_time[i] = stop_time(&sread_comp);
                            sread_cpu_time[i] = stop_cpu_time(&sread_cpu);

								// XXX: this part assumes BYTES_UNDER_P equals 7
								// dot product accross the row, 56 bytes (8 chunks) at a time
								uint128_t row_val = 0;
								size_t accum_count = 0;
								for (size_t raw_ind = 0, full_ind = 0; full_ind < n; raw_ind += 7, full_ind += 8) {
									// avoid overflow using mod when needed
									if ((accum_count += 8) > MAX_ACCUM_P) {
										row_val %= P57;
										accum_count = 8;
									}

									uint128_t data_val = raw_row[raw_ind] & CHUNK_MASK;
									row_val += data_val * challenge1[full_ind];

									for (int k = 1; k < 7; ++k) {
										data_val = (raw_row[raw_ind + k - 1] >> (64 - k*8))
											| ((raw_row[raw_ind + k] << (k*8)) & CHUNK_MASK);
										row_val += data_val * challenge1[full_ind + k];
									}

									data_val = raw_row[raw_ind + 6] >> 8;
									row_val += data_val * challenge1[full_ind + 7];
								}
								// XXX (end assumption that BYTES_UNDER_P equals 7)

								// mod final result and save to shared vector
								dot_prods1[i] = row_val % P57;

#ifdef POR_MMAP
								if (i == m-1) {
									free(raw_row);
								}
#endif // POR_MMAP
							}

#ifdef POR_MMAP
							munmap(fdmap, filenm);
#else // no MMAP
							free(raw_row);
							close(fd);
#endif // POR_MMAP

							fprintf(stderr, "thread %d finished matrix-vector mul\n", omp_get_thread_num());
						}

						double server_cpu_time = stop_cpu_time(&cpu_timer);
						double server_comp_time = stop_time(&timer);

						// write response back to client
						start_time(&timer);
						my_fwrite(dot_prods1, sizeof *dot_prods1, m, client);
						fflush(client);
						fprintf(stderr, "Wrote %"PRIu64" bytes to client.\n", m * sizeof *dot_prods1);

						// receive communication time from client and compute total, print out
						double comm_time = 0;
						my_fread(&comm_time, sizeof comm_time, 1, client);
						comm_time+= stop_time(&timer);
						fprintf(stderr, "***SERVER COMP TIME: %f ***\n***SERVER CPU  TIME: %f ***\n***SERVER COMM TIME: %f ***\n", server_comp_time, server_cpu_time, comm_time);

                        double sread_comp_max = 0.0;
                        double sread_cpu_tot = 0.0;
                        for (size_t i = 0; i < m; ++i) {
                            if (sread_comp_time[i]>sread_comp_max)
                                sread_comp_max = sread_comp_time[i];
                            sread_cpu_tot += sread_cpu_time[i];
                        }

                        fprintf(stderr, "***SERVER READ COMP TIME: %f ***\n***SERVER READ CPU  TIME: %f ***\n", sread_comp_max, sread_cpu_tot);
                        
                        free(sread_cpu_time);
                        free(sread_comp_time);
						free(challenge1);
						free(dot_prods1);
					}
					break;

				case 'R':
					/*retrieve stuff*/
					fprintf(stderr, "Entering Retrieve Mode...\n");

					// read request params from client
					uint32_t nhash, lbsize;
					uint64_t index, block_count, block_offset;
					// get index, read, and send one hash at a time
					char* hash = malloc(sinfo.hash_size);
					my_fread(&nhash, sizeof(uint32_t), 1, client);
					for (uint32_t i = 0; i < nhash; i++) {
						my_fread(&index, sizeof(uint64_t), 1, client);
						read_hash(index, hash, fmerkle, &sinfo);
						my_fwrite(hash, sinfo.hash_size, 1, client);
					}
					// read all needed blocks and send them to client
					my_fread(&block_count, sizeof(uint64_t), 1, client);
					my_fread(&block_offset, sizeof(uint64_t), 1, client);
					my_fread(&lbsize, sizeof(uint32_t), 1, client);
					send_blocks(block_offset, block_count, lbsize, dataMatrix, client, &sinfo);

					fflush(client);
					rewind(dataMatrix);
					free(hash);
					break;

				case 'U':
					/*update stuff*/
					fprintf(stderr, "Entering Update Mode...\n");

					// read first and last byte values
					uint64_t initial;
					uint64_t final;
					my_fread(&initial, sizeof(uint64_t), 1, client);
					fprintf(stderr, "Received initial index "_CHUNK_SPECIFIER"\n", initial);
					my_fread(&final, sizeof(uint64_t), 1, client);
					fprintf(stderr, "Received final index "_CHUNK_SPECIFIER"\n", final);

					// read new values in order and update
					unsigned char curByte;
					unsigned char* oldByte = &curByte; /*inited to get rid of warning*/
					uint64_t oldValue = 0;
					uint64_t newValue = 0;
					uint64_t chunkIndex;
					for (uint64_t curr = initial; curr <= final; curr++) {
						// get old chunk value at beginning of every chunk
						// and for first
						if ( (curr % sizeof(uint64_t)) == 0 || curr == initial) {
							oldValue = retrieveAndSend(curr, dataMatrix, client);
							newValue = oldValue;
							oldByte = (unsigned char*)&newValue;

							// if this is first
							// account for first not starting at beginning of chunk
							if (curr == initial) oldByte += (initial % sizeof(uint64_t));
						}

						// read next updated byte value from client
						my_fread(&curByte, 1, 1, client);

						// update the old value for this byte
						*oldByte = curByte;
						oldByte++;

						// if this is the last byte in a chunk or last overall,
						// update the database
						if ( (curr % sizeof(uint64_t)) == 7 || curr == final) {
							chunkIndex = (curr/sizeof(uint64_t))*sizeof(uint64_t);
							if (oldValue == newValue) {
								fprintf(stderr, "No Update Needed.\n");
							}else {
								fseek(dataMatrix, chunkIndex, SEEK_SET);
								my_fwrite(&newValue, sizeof(uint64_t), 1, dataMatrix);
								fflush(dataMatrix);
								fprintf(stderr, "Data Matrix Updated at "_CHUNK_SPECIFIER".\n", curr);
							}
						}

					}
					/*free(oldByte);*/
					rewind(dataMatrix);
					break;

				default:
					my_fwrite("ERROR: Invalid mode given\n", 1, 27, client);
			}
			fclose(client);
			return 0;
		} else if (c_pid > 0) {
			// parent needs to close socket given to child
			close(clientfd);
		} else {
			fprintf(stderr, "ERROR: fork unsuccessful\n");
		}
		//fclose(client);
	}

	printf("By return 0\n");
	fclose(dataMatrix);
	fclose(fmerkle);
	clear_work_space(&wspace);
	return 0;
}


void my_exits() {
	handler(0);
}


void handler(int signum) {
	printf("In the handler...\n");
	fclose(fconfig);
	fclose(fmerkle);
	fclose(dataMatrix);
	close(server);
	close(clientfd);
	clear_work_space(&wspace);
	_exit(0);
}


void my_fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	if (fread(ptr, size, nmemb, stream) != nmemb) {
		fprintf(stderr, "ERROR: did not read proper amount\n");
		exit(1);
	}
}


void my_fwrite(void* ptr, size_t size, size_t nmemb, FILE* stream) {
	if (fwrite(ptr, size, nmemb, stream) != nmemb) {
		fprintf(stderr, "ERROR: did not write proper amount\n");
		exit(1);
	}
}


uint64_t retrieveAndSend(uint64_t index, FILE* data, FILE* sock) {
	// seek to correct start of needed chunk in data file
	index -= (index % sizeof(uint64_t));
	fseek(data, index, SEEK_SET);

	// read chunk and send it to client
	uint64_t val;
	my_fread(&val, sizeof(uint64_t), 1, data);
	my_fwrite(&val, sizeof(uint64_t), 1, sock);
	fprintf(stderr, "Wrote block value "_CHUNK_SPECIFIER" from index "_CHUNK_SPECIFIER"\n", val, index);

	return val;
}


bool read_hash(uint64_t index, char* hash, FILE* merkle, const store_info_t* info) {
	printf("Reading hash from merkle tree:");
	if (fseek(merkle, (index + 1) * info->hash_size, SEEK_SET)) {
		fprintf(stderr, "ERROR: index "_CHUNK_SPECIFIER" out of bounds for merkle file\n", index);
		return false;
	}
	if (fread(hash, info->hash_size, 1, merkle) != 1) {
		fprintf(stderr, "ERROR reading from merkle file index "_CHUNK_SPECIFIER"\n", index);
		return false;
	}
	printf(" "_CHUNK_SPECIFIER"", index);
	fflush(stdout);
	printf("\n");

	return true;
}

bool send_blocks(uint64_t offset, uint64_t count, uint32_t lbsize, FILE* data, FILE* sock, const store_info_t* info) {
	printf("Reading blocks "_CHUNK_SPECIFIER"--"_CHUNK_SPECIFIER" from data\n", offset, offset+count-1);
	if (fseek(data, offset * info->block_size, SEEK_SET)) {
		fprintf(stderr, "ERROR: seek to block "_CHUNK_SPECIFIER" in data file\n", offset);
		return false;
	}

	char* block = malloc(info->block_size);
	if (count >= 2) {
		if (fread(block, info->block_size, 1, data) != 1) {
			fprintf(stderr, "ERROR: initial read from data file\n");
			return false;
		}
		my_fwrite(block, info->block_size, 1, sock);
		fflush(sock);
	}

	if (count >= 3) {
		for (uint32_t i = 0; i < count - 2; i++) {
			if (fread(block, info->block_size, 1, data) != 1) {
				fprintf(stderr, "ERROR: middle read from data file\n");
				return false;
			}
			my_fwrite(block, info->block_size, 1, sock);
		}
		fflush(sock);
	}

	if (count >= 1) {
		if (fread(block, lbsize, 1, data) != 1) {
			fprintf(stderr, "ERROR: final read from data file\n");
			return false;
		}
		my_fwrite(block, lbsize, 1, sock);
		fflush(sock);
	}
	printf("\n");
	free(block);

	return true;
}
