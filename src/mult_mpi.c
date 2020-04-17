// parallelize the audit process with mpi
// first arg: server config file

#include "integrity.h"
#include <inttypes.h>
#include <assert.h>

#include <mpi.h>

// 256K buffer
#define MYBS (1ul << 18)

// should rank 0 do work?
#define RANK0WORK (1)

int main(int argc, char **argv) {
	FILE *m,*config, *clientin, *clientout;
	off_t flenm;
	int range_start, range_row; // for each rank, holds starting index and length
	uint64_t *dot_prod1 = NULL, *dot_prod2 = NULL, *challenge1 = NULL, *challenge2 = NULL;
	int *range_starts = NULL, *range_rows = NULL;	// only used by rank 0
	uint64_t *dot_prods1 = NULL, *dot_prods2 = NULL; // only used by rank 0
	uint64_t nobj, i, nextmval, trash;
	int id, nt, j, k, ncol, nrow;
	char *bufm;
	double comm_time = 0, server_comp_time = 0;
	struct timespec timer;

	// change dupped clientfd (in) to 4, open as file
	dup2(0, 4);
	close(0);
	clientin = fdopen(4, "r");

	// change dupped clientfd(out) to 5, open as file
	dup2(1, 5);
	close(1);
	clientout = fdopen(5, "w");


	// dup stderr to stdout
	dup2(2, 1);

	// init mpi
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &id);

	// report process name
	{
		char hn[MPI_MAX_PROCESSOR_NAME+1];
		int len;
		MPI_Get_processor_name(hn, &len);
		hn[len] = '\0';
		fprintf(stderr, "rank %d started on %s\n", id, hn);
	}

	bufm = malloc(MYBS);

	// parse arguments
	if (argc < 2 || !(config = fopen(argv[1], "r"))) abort();

	// determine row and column sizes
	uint64_t numberofcols, numberofrows;
	fread(&numberofcols, sizeof numberofcols, 1, config);
	fread(&numberofrows, sizeof numberofrows, 1, config);
	ncol = (int)numberofcols;
	nrow = (int)numberofrows;

	// open data matrix
	int pathSize;
	fread(&pathSize, sizeof(int), 1, config);
	char path[pathSize];
	fread(path, 1, pathSize, config);
	path[pathSize] = '\0';
	fprintf(stderr, "Going to open file <%s> of length %d in rank %d\n", path, pathSize, id);
	m = fopen(path, "r");

	// make data matrix fully buffered
	setvbuf(m, bufm, _IOFBF, MYBS);

	// compute dimensions
	struct stat s;
	stat(path, &s);
	flenm = s.st_size;
	//fseek(m, 0, SEEK_END);
	//flenm = ftell(m);
	nobj = (double)flenm / sizeof nextmval;

	fprintf(stderr, "nobj: "_CHUNK_SPECIFIER", nrow: %d, ncol: %d\n", nobj, nrow, ncol);

	challenge1 = malloc(ncol * sizeof *challenge1);
	challenge2 = malloc(ncol * sizeof *challenge2);

	fprintf(stderr, "Completed prep work\n");

	// rank 0 determines and assigns work to be done
	if (id == 0) {
		MPI_Comm_size(MPI_COMM_WORLD, &nt);
		assert (RANK0WORK || nt >= 2);

		range_starts = malloc(nt * sizeof *range_starts);
		range_rows = malloc(nt * sizeof *range_rows);
		dot_prods1 = malloc(nrow * sizeof *dot_prods1);
		dot_prods2 = malloc(nrow * sizeof *dot_prods2);

		// get the challenge vectors from the client, send ack
		int bytesRead = 0, bytesWritten = 0;
		for (i = 0; i < ncol; ++i) {
			bytesRead += fread(&trash, sizeof trash, 1, clientin);
			challenge1[i] = trash;
		}
		for (i = 0; i < ncol; ++i) {
			bytesRead += fread(&trash, sizeof trash, 1, clientin);
			challenge2[i] = trash;
		}
		char ack = '1';
		if (fwrite(&ack, 1, 1, clientout) != 1) {
			fprintf(stderr, "Ack not sent\n");
			exit(2);
		}
		fflush(clientout);
		fprintf(stderr, "Read %d bytes from client.\n", bytesRead);
		fprintf(stderr, "Wrote %d bytes to file.\n", bytesWritten);

		// start timer for server computation time
		start_time(&timer);						/* START COMP TIMER */

		// rank 0 divy up the work
		fprintf(stderr, "total nobj = "_CHUNK_SPECIFIER" over %d processes\n", nobj, nt);

		// divide up the entire range
		range_starts[0] = 0;
		if (RANK0WORK)
			range_rows[0] = nrow / nt;
		else
			range_rows[0] = 0;
		fprintf(stderr, "Rank 0 - start: %d, rows: %d\n", range_starts[0], range_rows[0]);

		for (j = 1; j < nt; ++j) {
			// start where previous rank ended, take 1/(remaining threads) fraction of the remainder
			range_starts[j] = range_starts[j-1] + range_rows[j-1];
			range_rows[j] = (nrow - (range_starts[j-1] + range_rows[j-1])) / (nt - j);
			fprintf(stderr, "Rank %d - start: %d, rows: %d\n", j, range_starts[j], range_rows[j]);
		}
		fprintf(stderr, "Split all work in rank %d\n", id);

	}
	// communicate challenge vectors to all ranks
	MPI_Bcast(challenge1, ncol, MPI_UINT64_T, 0, MPI_COMM_WORLD);
	MPI_Bcast(challenge2, ncol, MPI_UINT64_T, 0, MPI_COMM_WORLD);

	// hand out each thread where to start and where 
	MPI_Scatter(range_starts, 1, MPI_INT, &range_start, 1, MPI_INT, 0, MPI_COMM_WORLD);
	MPI_Scatter(range_rows, 1, MPI_INT, &range_row, 1, MPI_INT, 0, MPI_COMM_WORLD);

	// work for each thread
	if (RANK0WORK || id >= 1) {
		//open challenge files
		fprintf(stderr, "In rank %d - start: %d, rows: %d\n", id, range_start, range_row);
		fseek(m, range_start * ncol * sizeof nextmval, SEEK_SET);

		fprintf(stderr, "Read work in rank %d\n", id);

		dot_prod1 = malloc(range_row * sizeof *dot_prod1);
		dot_prod2 = malloc(range_row * sizeof *dot_prod2);
		uint64_t sum1 = 0;
		uint64_t sum2 = 0;

		// do the matrix-vector mult
		for (j = 0; j < range_row; ++j) {
			for (k = 0; k < ncol; ++k) {
				if (fread(&nextmval, sizeof nextmval, 1, m) != 1)
						nextmval = 0;
				sum1 += n_mulmod2_preinv(nextmval, challenge1[k], PRIME_1, PREINV_PRIME_1);
				sum2 += n_mulmod2_preinv(nextmval, challenge2[k], PRIME_2, PREINV_PRIME_2);
			}
			dot_prod1[j] = sum1 % PRIME_1;
			dot_prod2[j] = sum2 % PRIME_2;
			sum1 = 0;
			sum2 = 0;
		}
		fprintf(stderr, "Completed work in rank %d\n", id);

	}

	// values back into one vector
	MPI_Gatherv(dot_prod1, range_row, MPI_UINT64_T, dot_prods1, range_rows,
					range_starts, MPI_UINT64_T, 0, MPI_COMM_WORLD);
	MPI_Gatherv(dot_prod2, range_row, MPI_UINT64_T, dot_prods2, range_rows,
					range_starts, MPI_UINT64_T, 0, MPI_COMM_WORLD);

	// rank 0 reports response vectors to client
	if (id == 0) {
		// stop server computation timer
		server_comp_time = stop_time(&timer);				/* STOP COMP TIMER */

		// write response back to client
		start_time(&timer);						/* START COMM TIMER */
		int bytesWritten = fwrite(dot_prods1, sizeof(uint64_t), nrow, clientout);
		bytesWritten += fwrite(dot_prods2, sizeof(uint64_t), nrow, clientout);
		fflush(clientout);
		fprintf(stderr, "Wrote %d bytes to client.\n", bytesWritten);

		// receive communication time from client and compute total, print out
		fread(&comm_time, sizeof(comm_time), 1, clientin);
		comm_time += stop_time(&timer);					/* STOP COMM TIMER */
		fprintf(stderr, "***SERVER COMP TIME: %f***\n***COMM TIME: %f***\n", server_comp_time, comm_time);
		
	}

	// cleanup
	fclose(m);
	free(bufm);
	free(challenge1);
	free(challenge2);
	if (id == 0) {
		fclose(clientin);
		fclose(clientout);
		free(range_starts);
		free(range_rows);
		free(dot_prods1);
		free(dot_prods2);
	}
	if (RANK0WORK || id > 0) { free(dot_prod1); free(dot_prod2); }

	MPI_Finalize();
	fprintf(stderr, "rank %d finished\n", id);

	return 0;
}
