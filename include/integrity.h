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
typedef unsigned __int128 uint128_t;

static inline uint64_t rand_mod_p(tinymt64_t* state) {
  static const uint64_t mask = (UINT64_C(1) << P_BITS) - 1;
  uint64_t val;
  do {
    val = tinymt64_generate_uint64(state) & mask;
  } while (val >= P57);
  return val;
}
