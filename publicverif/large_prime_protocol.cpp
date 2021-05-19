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



    //=========================================
    // Running the Public/Private Protocol
template<typename Field, bool PublicAudit=true>
bool Protocol(double& timeinit, double& timeaudit, double& timeserver,
           const Field& F, typename Field::RandIter& Rand, const size_t size) {

    timeinit=0., timeaudit=0., timeserver=0.;

    using FE_ptr = typename Field::Element_ptr;

    FFLAS::Timer chrono;
        // Generating a square matrix DB
    typename Field::Element_ptr ffmat;
    size_t m=size;
    size_t k=size;
    

    {
            //--------------------
            // Database Generation
        chrono.start();
        ffmat = FFLAS::fflas_new(F,m,k);
        FFLAS::frand(F, Rand, m,k, ffmat, k);
        WriteRaw256(F, m*k, ffmat, "/tmp/ffmat.bin");
        chrono.stop();
        
        std::clog << "[DATABASE] generated, " << chrono << std::endl;

            //--------------------
			// Client INIT
        chrono.start();

            // Random UU and VV=M^T UU
        FE_ptr uu = FFLAS::fflas_new(F,size,1);
        FFLAS::frand(F, Rand, size, uu, 1);

            // VV=M^T UU
        FE_ptr vv = FFLAS::fflas_new(F,size,1);
        FFLAS::fgemv(F,FFLAS::FflasTrans,m, k, F.one, ffmat, k, uu, 1, F.zero,vv,1);

            // Database is sent to Server and discarded
        FFLAS::fflas_delete(ffmat);

            // Ciphering VV in case of public audits
        if (PublicAudit) {
            std::vector<point_t> ww(size);
            int errors(0);
            scalar_t stmp;
            for(size_t i=0; i<size; ++i) {
                Integer2scalar(stmp, vv[i]);
                errors += crypto_scalarmult_ristretto255_base(
                    ww[i]._data,stmp._data);
            }
                // std::clog << "[CIPHER] " 
                //           << errors << " errors." << std::endl;
            assert(errors == 0);

            WritePoints(ww, "/tmp/porww.bin");
        }

            // Write all to files for auditors
        WriteRaw256(F, size, uu, "/tmp/poruu.bin");
        FFLAS::fflas_delete(uu);
        WriteRaw256(F, size, vv, "/tmp/porvv.bin");
        FFLAS::fflas_delete(vv);

        chrono.stop();
        timeinit += chrono.usertime();
    }

        //--------------------
        // Starting AUDIT
        //   AUDIT.1: Client challenge
        //            Client generates XX and sends it to the Server
    chrono.start();
    FE_ptr xx = FFLAS::fflas_new(F,1,size);
    FFLAS::frand(F, Rand, size, xx, 1);
    chrono.stop();
    timeaudit += chrono.usertime();

        //--------------------
        //   AUDIT.2: Server response
        //            Server responds with YY
    chrono.start(); 
    {
        FE_ptr yy = FFLAS::fflas_new(F,1,size);
        FE_ptr ffrow;

            // Server is computing the matrix-vector product row by row
        AllocateRaw256(F, k, ffrow);
        RowAllocatedRaw256DotProduct(F, m, k, ffrow, xx, yy, "/tmp/ffmat.bin");

            // Write yy to a file for the Client
        WriteRaw256(F, size, yy, "/tmp/poryy.bin");
        FFLAS::fflas_delete(yy,ffrow);
    }
    chrono.stop(); timeserver+=chrono.usertime();

        //--------------------
        //   AUDIT.3: Client verification
        //            Client verifies the Server response
    chrono.start();
    bool success(false);

        // 3.1: Loading the client secrets
    FE_ptr uu; ReadRaw256(F, size, uu, "/tmp/poruu.bin");
    FE_ptr vv; ReadRaw256(F, size, vv, "/tmp/porvv.bin");
        // 3.2: Receiving the server result
    FE_ptr yy; ReadRaw256(F, size, yy, "/tmp/poryy.bin");

        // 3.3: Computing u^T . y
    FE_ptr lhs = FFLAS::fflas_new(F,1,1), rhs = FFLAS::fflas_new(F,1,1);
    FFLAS::ParSeqHelper::Sequential seqH;
    FFLAS::fgemv(F,FFLAS::FflasNoTrans,1,size,F.one,uu,size,yy,1,F.zero,lhs,1,seqH);

        // 3.4a: public verification
    if (PublicAudit) {
        std::vector<point_t> ww(size);
        ReadPoints(ww, "/tmp/porww.bin");

        int errors(0);
        point_t result, mtmp;
        scalar_t sxx;

            // Computing W^x
        errors += crypto_scalarmult_ristretto255(
            result._data, Integer2scalar(sxx, xx[0])._data, ww[0]._data);
        for(size_t i=1; i<size; ++i) {
            errors += crypto_scalarmult_ristretto255(
                mtmp._data, Integer2scalar(sxx, xx[i])._data, ww[i]._data);
            errors += crypto_core_ristretto255_add(
                result._data, result._data, mtmp._data);
        }
            // std::clog << "[SCAMUL] " 
            //           << errors << " errors." << std::endl;
        assert(errors == 0);


            // Computing g^{u y}
        Integer2scalar(sxx, lhs[0]);
        errors += crypto_scalarmult_ristretto255_base(mtmp._data,sxx._data);

            // Checking whether g^{u^T y} == (g^v)^x
        success = areEqualPoints(result, mtmp);

        if (! success) {
            std::cerr << "W^x   : " << result << std::endl;
            std::cerr << "g^{uy}: " << mtmp << std::endl;
        }

        // 3.4b: private verification
    } else {
            // Computing v^T x
        FFLAS::fgemv(F,FFLAS::FflasNoTrans,1,size,F.one,vv,size,xx,1,F.zero,rhs,1,seqH);
            // Checking whether u^T y == v^T x
        success = F.areEqual(lhs[0],rhs[0]);
    }

    FFLAS::fflas_delete(uu,vv,xx,yy,lhs,rhs);
    chrono.stop();
    timeaudit += chrono.usertime();

    if (success)
        std::clog << "Audit\tPASS. \t" << timeinit << ',' << timeserver << ',' << timeaudit << std::endl;
    else
        std::clog << "Audit\tFAIL." << std::endl;

    return (!success);
}


template<typename Ints, typename Comps=Ints>
int tmain(){
        // argv[1]: size of the vector dotproduct to benchmark
    const size_t bits(252);
    const size_t size = k;

    srand( (int)seed);
    srand48(seed);
    Givaro::Integer::seeding(seed);

        //-------------------------
        // Ristretto255 prime order
   Givaro::Integer p("27742317777372353535851937790883648493");
    p += Givaro::Integer(1)<<=252;

    std::vector<double> timeinit(iters), timeaudit(iters), timeserver(iters);

    typedef Givaro::Modular<Ints,Comps> Field;
    Field F(p);
    typename Field::RandIter Rand(F,seed);

    bool success=true;

        //-------------------------
        // private Protocol
    success &= Protocol<Field,false>(timeinit[0], timeaudit[0], timeserver[0], F, Rand, size);

    for(size_t i=0; i<iters; ++i) {
        success &= Protocol<Field,false>(timeinit[i], timeaudit[i], timeserver[i], F, Rand, size);
    }

    std::sort(timeinit.begin(),timeinit.end());
    std::sort(timeaudit.begin(),timeaudit.end());
    std::sort(timeserver.begin(),timeserver.end());

    std::clog << (1000.*timeinit[iters/2]) << " ms\t: [SETUP] [PRIVATE] " << k  << " : " << mediandeviation(timeinit) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeserver[iters/2]) << " ms\t: [AUDIT SERVER] [PRIVATE] " << k  << " : " << mediandeviation(timeserver) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeaudit[iters/2]) << " ms\t: [AUDIT CLIENT] [PRIVATE] " << k  << " : " << mediandeviation(timeaudit) << "% (" << iters << ')' << std::endl;

        //-------------------------
        // public Protocol
    success &= Protocol<Field,true>(timeinit[0], timeaudit[0], timeserver[0], F, Rand, size);
    for(size_t i=0; i<iters; ++i) {
        success &= Protocol<Field,true>(timeinit[i], timeaudit[i], timeserver[i], F, Rand, size);
    }
    std::sort(timeinit.begin(),timeinit.end());
    std::sort(timeaudit.begin(),timeaudit.end());
    std::sort(timeserver.begin(),timeserver.end());

    std::clog << (1000.*timeinit[iters/2]) << " ms\t: [SETUP] [PUBLIC] " << k  << " : " << mediandeviation(timeinit) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeserver[iters/2]) << " ms\t: [AUDIT SERVER] [PUBLIC] " << k  << " : " << mediandeviation(timeserver) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeaudit[iters/2]) << " ms\t: [AUDIT CLIENT] [PUBLIC] " << k  << " : " << mediandeviation(timeaudit) << "% (" << iters << ')' << std::endl;


    return success;

}

int main(int argc, char **argv) {
    FFLAS::parseArguments(argc,argv,as);
    int r1 = tmain<Givaro::Integer>();
    return r1;
}
