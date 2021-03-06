/****************************************************************
 * Public/Private Proof Retreivability with low server storage
 * Requires:
 * \url{https://gmplib.org},
 * \url{https://github.com/linbox-team/givaro},
 * \url{http://www.openblas.net},
 * \url{https://linbox-team.github.io/fflas-ffpack},
 * \url{https://download.libsodium.org}.
 *
 ****************************************************************/

#include <fflas-ffpack/fflas-ffpack-config.h>
#include <iostream>
#include <typeinfo>
#include <vector>
#include <string>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <bitset>
#include <assert.h>

// default file name
#ifndef DATAF_NAME
#define DATAF_NAME ("/tmp/porscheme.bin")
#endif

#define INTEGER_NO_RNS 1

/****************************************************************
 * Elliptic curve
 ****************************************************************/

#include <sodium.h>
#define crypto_core_ristretto255_SCALARWORDS (crypto_core_ristretto255_SCALARBYTES>>3)
#define crypto_core_ristretto255_WORDS (crypto_core_ristretto255_BYTES>>3)

// libsodium scalars (elements modulo p)
union scalar_t
{
        // libsodium scalars as bytes ...
    unsigned char _data[crypto_core_ristretto255_SCALARBYTES];
        // ... or words
    std::uint64_t _word[crypto_core_ristretto255_SCALARWORDS];
};


// libsodium elliptic curve points
union point_t {
    unsigned char _data[crypto_core_ristretto255_BYTES];
    std::uint64_t _word[crypto_core_ristretto255_WORDS];
};



// test libsodium elements
bool areEqualPoints(const point_t& p, const point_t& q) {
    bool success(true);
    for(size_t i=0; i<crypto_core_ristretto255_WORDS; ++i)
        success &= (p._word[i] == q._word[i]);
    return success;
}


// io of libsodium elements
std::ostream& printuchar(std::ostream& out,
                         const unsigned char * p, size_t length) {
    const size_t HEXES(1+(length<<1));
    char phex[HEXES];
    sodium_bin2hex(phex, HEXES, p, length);
    return out << phex;
}

std::ostream& operator<<(std::ostream& out, const point_t& p) {
    return printuchar(out, p._data, crypto_core_ristretto255_BYTES);
}
std::ostream& operator<<(std::ostream& out, const scalar_t& p) {
    return printuchar(out, p._data, crypto_core_ristretto255_SCALARBYTES);
}


void WritePoints(const std::vector<point_t>& v,
                 const char * filename = DATAF_NAME) {
    FILE* dataf = fopen(filename, "w");
    assert (dataf);
    for(size_t i=0; i<v.size(); ++i) {
        fwrite(v[i]._word, 8, crypto_core_ristretto255_WORDS, dataf);
    }
    fclose(dataf);
}
void ReadPoints(std::vector<point_t>& v,
                const char * filename = DATAF_NAME) {
    FILE* dataf = fopen(filename, "r");
    for(size_t i=0; i<v.size(); ++i) {
        fread(v[i]._word, 8, crypto_core_ristretto255_WORDS, dataf);
    }
    fclose(dataf);
}

bool TestRWPoints(const std::vector<point_t>& A) {
    WritePoints(A);
    std::vector<point_t> B(A.size());
    ReadPoints(B);

    bool success = true;
    for(size_t i=0; i<A.size(); ++i) {
        bool areeq = areEqualPoints(A[i], B[i]);
        if (! areeq) {
            std::cerr << "A[" << i << "]: " << A[i] << " != "
                      << "B[" << i << "]: " << B[i] << std::endl;
        }
        success &= areeq;
    }
    if (success)
        std::clog << "TRWP\tPASS." << std::endl;
    else
        std::clog << "TRWP\tFAIL." << std::endl;

    return success;
}


/****************************************************************
 * Arbitrary precision arithmetic
 ****************************************************************/
#include <givaro/givinteger.h>
#include <givaro/givspyinteger.h>

// Creating a fixed-value 256 bits mpz_class
mpz_class FixedFourMpzClassElement() {
    mpz_t mexp;
    mexp->_mp_d = new mp_limb_t[4]; // allocates for 256 bits mpz
    mexp->_mp_alloc=4;				// 4 limbs allocated
    mexp->_mp_size=4;				// value on 4 limbs too
    mexp->_mp_d[3] = 1;				// nonzero value 1<<192
    mpz_class tmp(mexp);
    delete[] mexp->_mp_d;
    return tmp;
}

// Creating a 256 bits mpz_class
mpz_class MpzClassFourElement(const uint64_t& s,
                              const uint64_t& t,
                              const uint64_t& u,
                              const uint64_t& v)
{
    mpz_t mexp;
    mexp->_mp_d = new mp_limb_t[4]; // allocates for 256 bits mpz
    mexp->_mp_alloc=4;				// 4 limbs allocated
    mexp->_mp_size=4;				// value on 4 limbs too
    mexp->_mp_d[0] = s;
    mexp->_mp_d[1] = t;
    mexp->_mp_d[2] = u;
    mexp->_mp_d[3] = v;
    mpz_class tmp(mexp);
    delete[] mexp->_mp_d;
    return tmp;
}

// Allocating a vector of Givaro Integers (mpz_t)
// all initiated with a 256 bits default value (here 1<<192)
std::vector<Givaro::Integer>& IntegerAlloc256(std::vector<Givaro::Integer>& V,
                                              size_t n) {
    V.resize(n,FixedFourMpzClassElement());
    return V;
}

// Change the value of a Givaro preallocated integer
// on 256 bits with the four uint64_t
// gets: s + (t<<64) + (u<<128) + (v<<192)
Givaro::Integer& scalar2Integer(Givaro::Integer& i,
                                const uint64_t& s,
                                const uint64_t& t,
                                const uint64_t& u,
                                const uint64_t& v)
{
    Givaro::SpyInteger::get_mpz(i)->_mp_d[0]=s;
    Givaro::SpyInteger::get_mpz(i)->_mp_d[1]=t;
    Givaro::SpyInteger::get_mpz(i)->_mp_d[2]=u;
    Givaro::SpyInteger::get_mpz(i)->_mp_d[3]=v;
    Givaro::SpyInteger::get_mpz(i)->_mp_alloc=4;
    Givaro::SpyInteger::get_mpz(i)->_mp_size=4;
    return i;
};

// Change the value of a Givaro preallocated integer i,
// on 256 bits, with the libsodium scalar s
Givaro::Integer& scalar2Integer(Givaro::Integer& i, const scalar_t& s)
{
    return scalar2Integer(i, s._word[0], s._word[1], s._word[2], s._word[3]);
};

// Change the value of a libsodium scalar s, on 256 bits,
// with the four fisrt limbs of a givaro integer
scalar_t& Integer2scalar(scalar_t& s, const Givaro::Integer& i)
{
    s._word[0]=Givaro::SpyInteger::get_mpz(i)->_mp_d[0];
    s._word[1]=Givaro::SpyInteger::get_mpz(i)->_mp_d[1];
    s._word[2]=Givaro::SpyInteger::get_mpz(i)->_mp_d[2];
    s._word[3]=Givaro::SpyInteger::get_mpz(i)->_mp_d[3];
    return s;
};

template<typename Field>
std::vector<Givaro::Integer>& IntegerCreate256(std::vector<Givaro::Integer>& V,
                                               size_t n) {
    V.resize(n,FixedFourMpzClassElement());
    return V;
}

template<typename Field>
void WriteRaw256(const Field& F, size_t k, typename Field::ConstElement_ptr A,
                 const char * filename = DATAF_NAME) {
    FILE* dataf = fopen(filename, "w");
    assert (dataf);
    for(size_t i=0; i<k; ++i) {
        fwrite(Givaro::SpyInteger::get_mpz( A[i] )->_mp_d, 8, 4, dataf);
//         std::clog << "writ: " << A[i] << std::endl;
    }
    fclose(dataf);
}

template<typename Field>
void AppendRaw256(const Field& F, size_t k, typename Field::ConstElement_ptr A,
                 const char * filename = DATAF_NAME) {
    FILE* dataf = fopen(filename, "a");
    assert (dataf);
    for(size_t i=0; i<k; ++i) {
        fwrite(Givaro::SpyInteger::get_mpz( A[i] )->_mp_d, 8, 4, dataf);
//         std::clog << "writ: " << A[i] << std::endl;
    }
    fclose(dataf);
}


/****************************************************************
 * Exact linear algebra
 ****************************************************************/

#include <fflas-ffpack/utils/timer.h>
#include <fflas-ffpack/fflas/fflas.h>
#include <fflas-ffpack/utils/fflas_io.h>
#include <givaro/modular-integer.h>
#include <givaro/givcaster.h>

template<typename Field>
typename Field::Element_ptr&
ReadRaw256(const Field& F, size_t k, typename Field::Element_ptr& A,
           const char * filename = DATAF_NAME) {
    const size_t N(k<<5); // 256 bits = 32 bytes
    FILE* dataf = fopen(filename, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );
    fread(data_buf, 1, N, dataf);
    fclose(dataf);
    uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);

    A = FFLAS::fflas_new(F, k);
    for(size_t i=0; i<k; ++i) {
        A[i]=Givaro::Integer(MpzClassFourElement(data_in_64s[4*i+0],
                                                 data_in_64s[4*i+1],
                                                 data_in_64s[4*i+2],
                                                 data_in_64s[4*i+3]));
//         std::clog << "read: " << A[i] << std::endl;
    }
    free(data_buf);
    return A;
}

template<typename Field>
bool TestRW(const Field& F, size_t k, typename Field::ConstElement_ptr A) {
    WriteRaw256(F,k,A);
    typename Field::Element_ptr B;
    ReadRaw256(F,k,B);
    bool success = true;

    for(size_t i=0; i<k; ++i) {
        bool areeq = F.areEqual(A[i], B[i]);
        if (! areeq) {
            F.write(std::cerr << "A[" << i << "]: ", A[i]) << " != ";
            F.write(std::cerr << "B[" << i << "]: ", B[i]) << std::endl;
        }
        success &= areeq;
    }
    if (success)
        std::clog << "TRW\tPASS." << std::endl;
    else
        std::clog << "TRW\tFAIL." << std::endl;

    FFLAS::fflas_delete(B);
    return success;
}

template<typename Field>
typename Field::Element_ptr&
AllocateRaw256(const Field& F, size_t k, typename Field::Element_ptr& A) {
    A = FFLAS::fflas_new(F, k);
    for(size_t i=0; i<k; ++i) {
        A[i]=Givaro::Integer(FixedFourMpzClassElement());
    }
    return A;
}

template<typename Field>
typename Field::Element_ptr&
ReadAllocatedRaw256(const Field& F, size_t k, typename Field::Element_ptr& A,
                    const char * filename = DATAF_NAME) {
    const size_t N(k<<5); // 32 bytes per 256-bits element
    FILE* dataf = fopen(filename, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );
    fread(data_buf, 1, N, dataf);
    fclose(dataf);
    uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);

    for(size_t i=0; i<k; ++i) {
        scalar2Integer(A[i],
                       data_in_64s[4*i+0],
                       data_in_64s[4*i+1],
                       data_in_64s[4*i+2],
                       data_in_64s[4*i+3]);
//         std::clog << "read: " << A[i] << std::endl;
    }
    free(data_buf);
    return A;
}

Givaro::Integer fdot(const Givaro::Modular<Givaro::Integer>& F, const size_t N,
     const Givaro::Integer* x, const size_t incx,
     const Givaro::Integer* y, const size_t incy)
{
    Givaro::Integer d;
    F.assign(d, F.zero);
    const Givaro::Integer *  xi = x;
    const Givaro::Integer *  yi = y;
    for ( ; xi < x+N*incx; xi+=incx, yi+=incy )
        Givaro::Integer::axpyin(d, *xi, *yi);
    F.reduce(d);
    return d;
    }

#include <fcntl.h>
#include <unistd.h>
#include <omp.h>

#ifdef POR_MMAP
#include <sys/mman.h>
#endif
extern "C" {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wpointer-arith"
#include <integrity.h>
#pragma GCC diagnostic pop
}

template<typename Field>
typename Field::Element_ptr&
MatrixVectorRightbyDotProducts(const Field& F, size_t m, size_t k,
                               typename Field::ConstElement_ptr B,
                               typename Field::Element_ptr& C,
                               const char * filename = DATAF_NAME) {

    const size_t N(k<<5); // 32 bytes in per element

#pragma omp parallel
    {
        int fd = open(filename, O_RDONLY);
        assert (fd >= 0);
#ifdef POR_MMAP
        std::clog << "[ROWDP] MMAP, " << omp_get_num_threads() << " threads, on: " << omp_get_thread_num() << ".\n";
        void* fdmap = mmap(NULL, m*N, PROT_READ, MAP_PRIVATE, fd, 0);
        assert (fdmap != MAP_FAILED);
        uint8_t const* udmap = reinterpret_cast<uint8_t const*>(fdmap);
        close(fd);
#else // no MMAP
        std::clog << "[ROWDP] PREAD, " << omp_get_num_threads() << " threads, on: " << omp_get_thread_num() << ".\n";
        uint64_t *data_in_64s = reinterpret_cast<uint64_t*>(malloc(N));
        assert (data_in_64s);
#endif // POR_MMAP

        typename Field::Element_ptr A;
        AllocateRaw256(F, k, A);

#pragma omp for schedule(static) nowait
        for(size_t i=0; i<m; ++i) {
#ifdef POR_MMAP
            uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(udmap + (N*i));
#else // no MMAP
            my_pread(fd, data_in_64s, N, N*i);
#endif // POR_MMAP
            for(size_t j=0; j<k; ++j) {
                scalar2Integer(A[j],
                               data_in_64s[4*j+0],
                               data_in_64s[4*j+1],
                               data_in_64s[4*j+2],
                               data_in_64s[4*j+3]);
                    //         std::clog << "read: " << A[i] << std::endl;
            }
            F.assign( C[i], fdot(F,k,A,1,B,1) );
        }

        FFLAS::fflas_delete(A);
#ifdef POR_MMAP
        munmap(fdmap, m*N);
#else // no MMAP
        free(data_in_64s);
#endif // POR_MMAP

    }
    return C;
}


template<typename Field>
typename Field::Element_ptr&
LeftVectorMatrixbyDotProducts(const Field& F,
                              size_t m, size_t k,
                              typename Field::ConstElement_ptr B,
                              typename Field::Element_ptr& C,
                              const char * filename = DATAF_NAME) {

    const size_t N(k<<5); // 32 bytes in per element
#ifdef _LAPOR_MMAP_
    std::clog << "[LEFTDP] MMAP.\n";
    int fd = open(filename, O_RDONLY);
    assert (fd >= 0);
    void* fdmap = mmap(NULL, m*N, PROT_READ, MAP_PRIVATE, fd, 0);
    assert (fdmap != MAP_FAILED);
    uint8_t const* udmap = reinterpret_cast<uint8_t const*>(fdmap);
    close(fd);
#else
    std::clog << "[LEFTDP] FREAD.\n";
    FILE* dataf = fopen(filename, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );
#endif

    Givaro::ZRing<Givaro::Integer> ZZ;

    typename Field::Element_ptr A;
    AllocateRaw256(F, k, A);

    for (size_t i=0; i<m; i++){
#ifdef _LAPOR_MMAP_
        uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(udmap + (N*i));
#else
        fread(data_buf, 1, N, dataf);
        uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);
#endif
        for(size_t j=0; j<k; ++j) {
            scalar2Integer(A[j],
                           data_in_64s[4*j+0],
                           data_in_64s[4*j+1],
                           data_in_64s[4*j+2],
                           data_in_64s[4*j+3]);
        }

        FFLAS::faxpy(ZZ, k, B[i], A, 1, C, 1);

    }

    FFLAS::fflas_delete(A);

#ifdef _LAPOR_MMAP_
    munmap(fdmap, m*N);
#else
    fclose(dataf);
    free(data_buf);
#endif

    FFLAS::freduce(F,k,C,1);
    return C;
}


/****************************************************************
 * Median deviation
 ****************************************************************/

template<typename Vect> double mediandeviation(const Vect& v) {
    assert(v.size()>0);
    typename Vect::value_type median(v[v.size()/2]);
    double t1( median-v.front() );
    double t2( v.back()-median );
    return 100.*std::max(t1,t2)/median;
}



/****************************************************************
 * dotproduct in the exponents
 ****************************************************************/

template<typename Field>
point_t& crypto_dotproduct_ristretto255(point_t& result,
                                        const std::vector<point_t>& ww,
                                        typename Field::ConstElement_ptr xx) {
    int errors(0);
    point_t mtmp;
    scalar_t sxx;

        // Computing W^x
    errors += crypto_scalarmult_ristretto255(
        result._data, Integer2scalar(sxx, xx[0])._data, ww[0]._data);
    for(size_t i=1; i<ww.size(); ++i) {
        errors += crypto_scalarmult_ristretto255(
            mtmp._data, Integer2scalar(sxx, xx[i])._data, ww[i]._data);
        errors += crypto_core_ristretto255_add(
            result._data, result._data, mtmp._data);
    }
        // std::clog << "[SCAMUL] "
        //           << errors << " errors." << std::endl;
    assert(errors == 0);

    return result;
}


/****************************************************************
 * Merkle tree
 ****************************************************************/
#include <sys/types.h>
#include <sys/stat.h>
extern "C" {
    #include "merkle.h"
}

#define DEFAULT_DIGEST ("sha512-224")


/**
 * Create and save a Merkle tree of a given data file with specified blocksize
*/
int CreateAndSaveMerkle(char const * datapath, char const * configpath, char const * treepath, uint32_t blocksize) {
#ifdef _LAPOR_DETAILED_TIMINGS_
    FFLAS::Timer chrono; chrono.clear(); chrono.start();
#endif

    FILE *fin, *fmerkle, *ftree;
    struct stat s;
    off_t fileSize;
    // input file must exist
	if ((fin = fopen(datapath, "r")) == NULL) {
		printf("Input data file <%s> does not exist\n", datapath);
		return 2;
	}
    fmerkle = fopen(configpath, "w");
	ftree   = fopen(treepath, "w");
    // get file size
	stat(datapath, &s);
	fileSize = s.st_size;

    // initiate merkle tree structure
	store_info_t merkleinfo;
	work_space_t wspace;
    merkleinfo.hash_nid = OBJ_txt2nid(DEFAULT_DIGEST);
	merkleinfo.block_size = blocksize;
	merkleinfo.size = fileSize;

    store_info_fillin(&merkleinfo);
	init_work_space(&merkleinfo, &wspace);
    // create merkle tree over data - stored in ftree
	init_root(fin, ftree, &merkleinfo, &wspace);
	rewind(fin);

	// store details in merkle config with root
	store_info_store(fmerkle, true, &merkleinfo);
    fclose(fin);
    fclose(fmerkle);
    fclose(ftree);

#ifdef _LAPOR_DETAILED_TIMINGS_
    chrono.stop();
    std::clog << "[MERKLE] Tree/root creation: " << chrono << std::endl;
#endif
    return 0;
}

/**
 * Check Merkle tree root of given data, root should be in configpath
*/
int MerkleVerif(char const * datapath, char const * configpath) {
#ifdef _LAPOR_DETAILED_TIMINGS_
    FFLAS::Timer chrono; chrono.clear(); chrono.start();
#endif

    FILE *fin, *fmerkleconfig;
    // input file must exist
	if ((fin = fopen(datapath, "rw")) == NULL) {
		printf("Input data file <%s> does not exist\n", datapath);
		return 2;
	}
    if ((fmerkleconfig  = fopen(configpath, "r+")) == NULL) {
		fprintf(stderr, "Merkle Config file <%s> does not exist\n", configpath);
		return 3;
	}
    // load merkle context
	store_info_t sinfo, cinfo;
	work_space_t wspace, cwspace;
	read_req_t rreq;
	uint64_t bufsize = 1024;
	char* buf = (char *) malloc(bufsize);
	if (store_info_load(fmerkleconfig, true, &sinfo) <=0) {
		fprintf(stderr, "Improper Merkle config\n");
		return 4;
	}
    rewind(fmerkleconfig);
    if (store_info_load(fmerkleconfig, true, &cinfo) <=0) {
		fprintf(stderr, "Improper Merkle config\n");
		return 4;
	}
	init_work_space(&sinfo, &wspace);
	update_signature(&sinfo, wspace.ctx);
    init_work_space(&cinfo, &cwspace);
	update_signature(&cinfo, cwspace.ctx);
    init_root(fin, NULL, &cinfo, &cwspace);
    fclose(fin);
    fclose(fmerkleconfig);
    int checkroot = memcmp(cinfo.root, sinfo.root, sinfo.hash_size);

#ifdef _LAPOR_DETAILED_TIMINGS_
    chrono.stop();
    std::clog << "[MERKLE] root verification: " << chrono << std::endl;
#endif

    return checkroot;
}
