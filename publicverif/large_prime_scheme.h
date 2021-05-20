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
    const size_t N(k<<5);
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

template<typename Field>
typename Field::Element_ptr&
RowAllocatedRaw256DotProduct(const Field& F, size_t m, size_t k, typename Field::Element_ptr& A,
                             typename Field::ConstElement_ptr B,
                             typename Field::Element_ptr& C,
                             const char * filename = DATAF_NAME) {

    const size_t N(k<<5); // 32 bytes in per element
    FILE* dataf = fopen(filename, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );

    for (size_t i=0; i<m; i++){
        
        fread(data_buf, 1, N, dataf);
        uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);
        for(size_t j=0; j<k; ++j) {
            scalar2Integer(A[j],
                           data_in_64s[4*j+0],
                           data_in_64s[4*j+1],
                           data_in_64s[4*j+2],
                           data_in_64s[4*j+3]);
                //         std::clog << "read: " << A[i] << std::endl;
        }
        F.assign( C[i], FFLAS::fdot(F,k,A,1,B,1) );
        
    }
    fclose(dataf);

    free(data_buf);
    return C;
}


template<typename Field>
typename Field::Element_ptr&
RowAllocatedRaw256left(const Field& F, 
                       size_t m, size_t k, typename Field::Element_ptr& A,
                       typename Field::ConstElement_ptr B,
                       typename Field::Element_ptr& C,
                       const char * filename = DATAF_NAME) {

    const size_t N(k<<5); // 32 bytes in per element
    FILE* dataf = fopen(filename, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );

    Givaro::ZRing<Givaro::Integer> ZZ;

    for (size_t i=0; i<m; i++){
        
        fread(data_buf, 1, N, dataf);
        uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);
        for(size_t j=0; j<k; ++j) {
            scalar2Integer(A[j],
                           data_in_64s[4*j+0],
                           data_in_64s[4*j+1],
                           data_in_64s[4*j+2],
                           data_in_64s[4*j+3]);
                //         std::clog << "read: " << A[i] << std::endl;
        }
        
        FFLAS::faxpy(ZZ, k, B[i], A, 1, C, 1);
        
    }
    fclose(dataf);
    free(data_buf);

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
    


