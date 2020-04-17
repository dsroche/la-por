// Cloud Server Script
// first arg is config file
// second arg is merkle file
// third arg is port number to listen on

#include "integrity.h"
#include <signal.h>
#include <getopt.h>

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
			"	-m --MPIhosts		path to hostfile for MPI, giving IPs and allocations of machines\n"
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
	char* hostfile = NULL;

	// register handler and make it run at exit as well
	signal(SIGINT, handler);
	signal(SIGTERM, handler);
	atexit(my_exits);

	// handle command line arguments
	struct option longopts[] = {
		{"port", required_argument, NULL, 'p'},
		{"MPIhosts", required_argument, NULL, 'm'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	while (true) {
		switch (getopt_long(argc, argv, "p:m:vh", longopts, NULL)) {
			case -1:
				goto done_opts;

			case 'p':
				port = atoi(optarg);
				break;

			case 'm':
				hostfile = optarg;
				break;

			case 'v':
				verbose = 1;
				break;

			case '?':
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

			// convert socket to FILE* can only happen if we are NOT
			// doing an audit (because of exec)
			client = NULL;
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
					fprintf(stderr, "Entering Audit Mode...\n");

					// exec audit protocol and close
					char* args[] = {"mpirun", "-v", "-np", "1", "mult_mpi", argv[optind], NULL};
					if (hostfile) {
						args[2] = "-hostfile";
						args[3] = hostfile;
					}
					dup2(clientfd, 1); // dup client to stdin so mpi can pass it
					dup2(clientfd, 0); // dido but for stdout
					execvp(args[0], args);
					perror("ERROR: execv failed\n");
					break;

				case 'R':
					client = fdopen(clientfd, "r+");
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
				        client = fdopen(clientfd, "r+");
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
				        client = fdopen(clientfd, "r+");
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
