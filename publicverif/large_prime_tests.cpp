#include "large_prime_scheme.h"

#include <fflas-ffpack/utils/args-parser.h>

static size_t iters = 3 ;
static size_t k = 512 ;
static size_t m = 512 ;
static size_t seed= time(NULL);
static Argument as[] = {
    { 'm', "-m M", "Set the row dimension of the matrix.",                    TYPE_INT , &m },
    { 'k', "-k K", "Set the col dimension of the matrix.",                    TYPE_INT , &k },
    { 'i', "-i R", "Set number of repetitions.",                            TYPE_INT , &iters },
    { 's', "-s S", "Sets seed.",				TYPE_INT , &seed },
    END_OF_ARGUMENTS
};

// ======================================================
#define NUM_RAND_BYTES (4)
static inline const void* get_rand_bytes() {
    static long r;
    r = mrand48();
    return (void*)&r;
}


int straightmain() {

    clock_t start, end;
    double cpu_time_used;

    const size_t bits(252);
    const size_t size = k;
    const size_t N(size<<5);


        // create random file
        //FILE* dataf = tmpfile();
    {
        FILE* dataf = fopen(DATAF_NAME, "w");
        assert (dataf);
        uint64_t dataf_len = 0;
        start = clock();
        while (dataf_len + NUM_RAND_BYTES <= N) {
            fwrite(get_rand_bytes(), 1, NUM_RAND_BYTES, dataf);
            dataf_len += NUM_RAND_BYTES;
        }
        if (dataf_len < N) {
            assert (N - dataf_len < NUM_RAND_BYTES);
            fwrite(get_rand_bytes(), 1, (size_t)(N - dataf_len), dataf);
            dataf_len = N;
        }
        end = clock();
        cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
        printf("[RANDBYTES] file gen time: %f ms\n", cpu_time_used*1000.0);
        fclose(dataf);
    }

        // ===========================================================
        // checks
    printf("[MAINT] Ristretto255 bytes : %zu & scalar : %zu\n", crypto_core_ristretto255_BYTES, crypto_core_ristretto255_SCALARBYTES);

    scalar_t rexp;
    crypto_core_ristretto255_scalar_random(rexp._data);


    printf("[SCALT] %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu\n", rexp._data[0], rexp._data[1], rexp._data[2], rexp._data[3],rexp._data[4+0], rexp._data[4+1], rexp._data[4+2], rexp._data[4+3]);
    printf("[4WORD] %zu, %zu, %zu, %zu\n", rexp._word[0], rexp._word[1], rexp._word[2], rexp._word[3]);

    Givaro::Integer iexp("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567"); // an integer stored on at  least 256 bits
    scalar2Integer(iexp, rexp);
    std::clog << "[GIVARO] " << iexp << std::endl;


        // Checking
    Givaro::Integer scal(rexp._data[0]), word(rexp._word[0]);

    Givaro::Integer sixtyfour(1); sixtyfour <<= 64;
    Givaro::Integer eight(1); eight <<= 8;

    std::clog << "[CHECK1] " << (iexp % sixtyfour) - word << std::endl;
    std::clog << "[CHECK2] " << (word % eight) - scal << std::endl;

        // ===========================================================
        // benchmarks

    start = clock();
    FILE* dataf = fopen(DATAF_NAME, "r");
    unsigned char* data_buf = reinterpret_cast<unsigned char*>( calloc(N, 1) );
    fread(data_buf, 1, N, dataf);
    fclose(dataf);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("[FREAD  ] : %f ms\n", cpu_time_used*1000.0);
    uint64_t const* data_in_64s = reinterpret_cast<uint64_t const*>(data_buf);


    start = clock();
    std::vector<Givaro::Integer> ivect; IntegerAlloc256(ivect, size);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("[VIALLOC] : %f ms\n", cpu_time_used*1000.0);


    start = clock();
    std::vector<scalar_t> svect(size);
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("[STALLOC] : %f ms\n", cpu_time_used*1000.0);


    start = clock();
    for(size_t i=0; i<size; ++i) {
        scalar2Integer(ivect[i],
                       data_in_64s[4*i],
                       data_in_64s[4*i+1],
                       data_in_64s[4*i+2],
                       data_in_64s[4*i+3]);
    }
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("[VIASSIG] : %f ms\n", cpu_time_used*1000.0);

    start = clock();
    for(size_t i=0; i<size; ++i)
        for(size_t j=0; j<4; ++j)
            svect[i]._word[j] = data_in_64s[4*i+j];
    end = clock();
    cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("[STASSIG] : %f ms\n", cpu_time_used*1000.0);


    free(data_buf);

    return 0;
}




template<typename Ints, typename Comps=Ints>
int misctests(const Givaro::Integer& tp, const size_t iterate=iters){
    typedef Givaro::Modular<Ints,Comps> Field;

    FFLAS::Timer chrono;
    double time=0., timeio=0., timegen=0.,
        timewri=0., timerea=0., timeall=0.,
        timerar=0., timeral=0., timedtp=0.;
    Givaro::Integer p(tp);
    Ints ip; Givaro::Caster<Ints,Givaro::Integer>(ip,p);
    Givaro::Caster<Givaro::Integer,Ints>(p,ip); // to check consistency
    Field F(ip);
    F.write(std::clog) << std::endl;
    
    for (size_t loop=0;loop<iters;loop++){

        typename Field::Element mtmp, rtmp;

        typename Field::RandIter Rand(F,seed += seed);
        typename Field::Element_ptr ffrow, ffvect, ffres, dpres, ffmat;

        chrono.clear();chrono.start(); {
            ffmat = FFLAS::fflas_new(F,m,k);
        }
        chrono.stop(); timeall+=chrono.realtime();

        chrono.clear();chrono.start(); {
            FFLAS::frand(F, Rand, m,k, ffmat, k);
        }
        chrono.stop(); timegen+=chrono.realtime();

        ffvect = FFLAS::fflas_new(F,k,1);
        FFLAS::frand(F, Rand, k, ffvect, 1);
        ffres  = FFLAS::fflas_new(F,m,1);
        FFLAS::ParSeqHelper::Sequential seqH;
        FFLAS::fgemv(F,FFLAS::FflasNoTrans,m,k,F.one,ffmat,k,ffvect,1,F.zero,ffres,1,seqH);

        // FFLAS::WriteMatrix(std::cerr<<"A="<<std::endl,F, m,k,ffmat,k);
        // FFLAS::WriteMatrix(std::cerr<<"x="<<std::endl,F, k,1,ffvect,1);
        // FFLAS::WriteMatrix(std::cerr<<"Ax="<<std::endl,F, m,1,ffres,1);
            // END Checks ---------

        // TestRW(F, m*k, ffmat);
    
        chrono.clear();chrono.start(); {
            WriteRaw256(F, m*k, ffmat, "/tmp/ffmat.bin");
            FFLAS::fflas_delete(ffmat);
        }
        chrono.stop(); timewri+=chrono.realtime();

        chrono.clear();chrono.start(); {
            AllocateRaw256(F, k, ffrow);
        }
        chrono.stop(); timeral+=chrono.realtime();

        chrono.clear();chrono.start(); {
            dpres  = FFLAS::fflas_new(F,m,1);
            RowAllocatedRaw256DotProduct(F, m, k, ffrow, ffvect, dpres, "/tmp/ffmat.bin");
        }
        chrono.stop(); timedtp+=chrono.realtime();

        // FFLAS::WriteMatrix(std::cerr<<"dpres="<<std::endl,F, m,1,dpres,1);

        if (FFLAS::fequal(F, m, dpres, 1, ffres, 1))
            std::clog << "DP/W\tPASS." << std::endl;
        else
            std::clog << "DP/W\tFAIL." << std::endl;

        FFLAS::fflas_delete(ffvect,ffrow,ffres,dpres);   
    }

    std::clog << (1000.*timeall/double(iters)) << " ms\t: Allocate FFLAS Vector " << k  << std::endl;
    std::clog << (1000.*timegen/double(iters)) << " ms\t: Generate random modular Vector " << k  << std::endl;
    std::clog << (1000.*timewri/double(iters)) << " ms\t: Write Raw256 Vector " << k  << std::endl;
    std::clog << (1000.*timerea/double(iters)) << " ms\t: Read Raw256 Vector " << k  << std::endl;
    std::clog << (1000.*timeral/double(iters)) << " ms\t: Allocate Raw256 Vector " << k  << std::endl;
    std::clog << (1000.*timerar/double(iters)) << " ms\t: preallocated Read Raw256 Vector " << k  << std::endl;
    std::clog << (1000.*timedtp/double(iters)) << " ms\t: dotproduct & preallocated Read Raw256 Vector " << k  << std::endl;

    return 0;
    
};

template<typename Ints, typename Comps=Ints>
int miscmain(){
        // argv[1]: size of the vector dotproduct to benchmark
    const size_t bits(252);
    const size_t size = k;

    srand( (int)seed);
    srand48(seed);
    Givaro::Integer::seeding(seed);

    Givaro::Integer p("27742317777372353535851937790883648493");
    p += Givaro::Integer(1)<<=252;

        // misctests<Ints,Comps>(p);
    return misctests<Ints,Comps>(p, 1);
}


int main(int argc, char **argv) {
    FFLAS::parseArguments(argc,argv,as);

    int r0 = straightmain();
    int r1 = miscmain<Givaro::Integer>();

    return r0+r1;
}
