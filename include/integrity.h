#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "merkle.h"
#include "tinymt64.h"
#include "mytimer.h"

#if __APPLE__
	#define _CHUNK_SPECIFIER "%llu"
#else
	#define _CHUNK_SPECIFIER "%lu"
#endif

#define P57 (UINT64_C(144115188075855859))
#define P_BITS (57)
#define BYTES_UNDER_P (7)
#define CHUNK_ALIGN (56)
// MAX_ACCUM_P is the most products you can accum in 128 bits before overflow
#define MAX_ACCUM_P (1 << 15)
//#define MAX_ACCUM_P (1) // FIXME remove
typedef unsigned __int128 uint128_t;

static inline uint64_t rand_mod_p(tinymt64_t* state) {
  static const uint64_t mask = (UINT64_C(1) << P_BITS) - 1;
  uint64_t val;
  do {
    val = tinymt64_generate_uint64(state) & mask;
  } while (val >= P57);
  return val;
}

static inline void my_pread(int fd, void* buf, size_t count, off_t offset) {
	ssize_t res = pread(fd, buf, count, offset);
	if (res == count)
		return;
	size_t got = 0;
	while (1) {
		if (res > 0) {
			got += res;
			if (got >= count)
				return;
		}
		else if (res == 0) {
			// EOF; zero out the rest
			memset(buf + got, 0, count - got);
			return;
		}
		else {
			perror("pread in my_pread");
			exit(10);
		}
		res = pread(fd, buf + got, count - got, offset + got);
	};
}

static inline void my_pwrite(int fd, const void * buf, size_t count, off_t offset) {
	ssize_t res = pwrite(fd, buf, count, offset);
	if (res == count)
		return;
	size_t gave = 0;
	while (1) {
		if (res > 0) {
			gave += res;
			if (gave >= count)
				return;
		}
		else if (res == 0) {
			// strange
			fprintf(stderr, "ERROR: pwrite couldn't write any more bytes\n");
			exit(10);
		}
		else {
			perror("pwrite in my_pwrite");
			exit(10);
		}
		res = pwrite(fd, buf + gave, count - gave, offset + gave);
	};
}
