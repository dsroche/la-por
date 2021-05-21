#LA-PoR publicly verifiable makefile

# easy to modify OPTFLAGS on the cmdline
OPTFLAGS=-Ofast -march=native -Wall -Wno-unused-variable -DNDEBUG
CXXFLAGS += ${OPTFLAGS} 


##  openssl
CXXFLAGS += `pkg-config openssl --cflags`
LOADLIBES += `pkg-config openssl --libs`

##  libsodium
CXXFLAGS += `pkg-config libsodium --cflags`
LOADLIBES += `pkg-config libsodium --libs`

##  FFLAS-FFPACK & GIVARO
CXXFLAGS += `pkg-config fflas-ffpack --cflags`
LOADLIBES += `pkg-config fflas-ffpack --libs`

## LA-PoR Merkle tree utils
MRKDIR=../build/lib
MRKINC=../merkle/include
CXXFLAGS += -I${MRKINC} -Drestrict=__restrict__
LOADLIBES+= -L${MRKDIR} -lmerkle


## Hard path setting
HARDLIBES = ${subst -L,, ${shell pkg-config fflas-ffpack --libs-only-L}}
LOADLIBES += ${HARDLIBES:%=-Wl,-rpath -Wl,%}

all: large_prime_protocol

large_prime_protocol:large_prime_scheme.h
