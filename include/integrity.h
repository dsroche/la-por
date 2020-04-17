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
#include "flint2.h"
#include "merkle.h"
#include "tinymt64.h"
#include "mytimer.h"

#if __APPLE__
	#define _CHUNK_SPECIFIER "%llu"
#else
	#define _CHUNK_SPECIFIER "%lu"
#endif

