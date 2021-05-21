#include "large_prime_scheme.h"

#include <fflas-ffpack/utils/args-parser.h>

static size_t iters = 3 ;
static size_t k = 512 ;
static size_t m = 512 ;
static size_t seed= time(NULL);
static bool randomDB(true);
static bool runServer(true);
static std::string DATABASEF_NAME("/tmp/ffmat.bin");
static Argument as[] = {
    { 'm', "-m M", "Set the row dimension of the matrix.",  TYPE_INT , &m },
    { 'k', "-k K", "Set the col dimension of the matrix.",  TYPE_INT , &k },
    { 'i', "-i R", "Set number of repetitions.",            TYPE_INT , &iters },
    { 's', "-s S", "Sets seed.",							TYPE_INT , &seed },
    { 'f', "-f finame", "Set the database filename.",	TYPE_STR , &DATABASEF_NAME },
    { 'r', "-r Y/N", "Generate a random database.",		TYPE_BOOL , &randomDB },
    { 'e', "-e Y/N", "Run server part.",		TYPE_BOOL , &runServer },
    END_OF_ARGUMENTS
};



    //=========================================
    // Running the Public/Private Protocol
template<typename Field, bool PublicAudit=true>
bool Protocol(double& timeinit, double& timeaudit, double& timeserver,
              const Field& F, typename Field::RandIter& Rand,
              const size_t m, const size_t k,
              const char * filename = DATAF_NAME) {

    timeinit=0., timeaudit=0., timeserver=0.;

    using FE_ptr = typename Field::Element_ptr;

    FFLAS::Timer chronoinit, chronoserver, chronoaudit, chronoauditr;
    chronoinit.clear(); chronoserver.clear();
    chronoaudit.clear(); chronoauditr.clear();

    {
            //--------------------
			// Client INIT
        chronoinit.start();

            // Random UU and VV=M^T UU
        FE_ptr uu = FFLAS::fflas_new(F,m,1);
        FFLAS::frand(F, Rand, m, uu, 1);

            // VV=M^T UU
        FE_ptr vv = FFLAS::fflas_new(F,k,1);
        {
            FFLAS::fzero(F, k, vv, 1);
            if (runServer) {
                    // Creating the control vector with the database
                FE_ptr ffrow;
                AllocateRaw256(F, k, ffrow);
                RowAllocatedRaw256left(F, m, k, ffrow, uu, vv,
                                       DATABASEF_NAME.c_str());
                FFLAS::fflas_delete(ffrow);
            } else {
                    // ... or just a simulation
                FFLAS::fassign(F, std::min(k,m), uu, 1, vv, 1);
            }
        }


            // Ciphering VV in case of public audits
        if (PublicAudit) {
            std::vector<point_t> ww(k);
            int errors(0);
            scalar_t stmp;
            for(size_t i=0; i<k; ++i) {
                Integer2scalar(stmp, vv[i]);
                errors += crypto_scalarmult_ristretto255_base(
                    ww[i]._data,stmp._data);
            }
                // std::clog << "[CIPHER] "
                //           << errors << " errors." << std::endl;
            assert(errors == 0);

            WritePoints(ww, "/tmp/porww.bin");
        }   // ww is deleted by the end of this block

            // Write all to files for auditors
        WriteRaw256(F, m, uu, "/tmp/poruu.bin");
        FFLAS::fflas_delete(uu);
        WriteRaw256(F, k, vv, "/tmp/porvv.bin");
        FFLAS::fflas_delete(vv);

        chronoinit.stop();
        timeinit += chronoinit.realtime();
    }

        //--------------------
        // Starting AUDIT
        //   AUDIT.1: Client challenge
        //            Client generates XX and sends it to the Server
    chronoaudit.start();
    FE_ptr xx = FFLAS::fflas_new(F,k);
    FFLAS::frand(F, Rand, k, xx, 1);
    chronoaudit.stop();
    timeaudit += chronoaudit.realtime();

        //--------------------
        //   AUDIT.2: Server response
        //            Server responds with YY
    chronoserver.start();
    {
        FE_ptr yy = FFLAS::fflas_new(F,m);
        if (runServer) {
                // Server is computing the matrix-vector product row by row
            FE_ptr ffrow;
            AllocateRaw256(F, k, ffrow);
            RowAllocatedRaw256DotProduct(F, m, k, ffrow, xx, yy, DATABASEF_NAME.c_str());
            FFLAS::fflas_delete(ffrow);
        } else {
                // ... or just a simulation
            FFLAS::fassign(F, std::min(m,k), xx, 1, yy, 1);
        }
        
            // Write yy to a file for the Client
        WriteRaw256(F, m, yy, "/tmp/poryy.bin");
        FFLAS::fflas_delete(yy);
    }
    chronoserver.stop(); timeserver+=chronoserver.usertime();

        //--------------------
        //   AUDIT.3: Client verification
        //            Client verifies the Server response
    chronoauditr.start();
    bool success(false);

        // 3.1: Loading the client secrets
    FE_ptr uu; ReadRaw256(F, m, uu, "/tmp/poruu.bin");
    FE_ptr vv; ReadRaw256(F, k, vv, "/tmp/porvv.bin");
        // 3.2: Receiving the server result
    FE_ptr yy; ReadRaw256(F, m, yy, "/tmp/poryy.bin");

        // 3.3: Computing u^T . y
    typename Field::Element lhs, rhs; F.init(lhs); F.init(rhs);
    F.assign(lhs, FFLAS::fdot(F, m, uu, 1, yy, 1) );

        // 3.4a: public verification
    if (PublicAudit) {
        std::vector<point_t> ww(k);
        ReadPoints(ww, "/tmp/porww.bin");

            // Computing W^x
        point_t plhs, prhs;
        crypto_dotproduct_ristretto255<Field>(prhs, ww, xx);

            // Computing g^{u y}
        scalar_t slhs; Integer2scalar(slhs, lhs);
        int error = crypto_scalarmult_ristretto255_base(plhs._data,slhs._data);
        assert(error == 0);

            // Checking whether g^{u^T y} == (g^v)^x
        success = areEqualPoints(plhs, prhs);

        if (! success) {
            std::cerr << "W^x   : " << prhs << std::endl;
            std::cerr << "g^{uy}: " << plhs << std::endl;
        }

        // 3.4b: private verification
    } else {
            // Computing v^T x
        F.assign(rhs, FFLAS::fdot(F, k, vv, 1, xx, 1) );
            // Checking whether u^T y == v^T x
        success = F.areEqual(lhs,rhs);
    }

    FFLAS::fflas_delete(uu,vv,xx,yy);
    chronoauditr.stop();
    timeaudit += chronoauditr.usertime();

    if (success)
        std::clog << "Audit\tPASS. \t" << chronoinit << ',' << chronoserver << ',' << (chronoaudit += chronoauditr) << std::endl;
    else
        std::clog << "Audit\tFAIL." << std::endl;

    return (!success);
}


template<typename Ints, typename Comps=Ints>
int tmain(){
        // argv[1]: size of the vector dotproduct to benchmark
    const size_t bits(252);

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


    if (randomDB) {
            //--------------------
            // Random Database Generation
        FFLAS::Timer chrono; chrono.clear(); chrono.start();
        typename Field::Element_ptr ffmat = FFLAS::fflas_new(F,k);
        FFLAS::frand(F, Rand, k, ffmat, 1);
        WriteRaw256(F, k, ffmat, DATABASEF_NAME.c_str());
        for(size_t i=1; i<m; ++i) {
            FFLAS::frand(F, Rand, k, ffmat, 1);
            AppendRaw256(F, k, ffmat, DATABASEF_NAME.c_str());
        }
            // Database is sent to Server and discarded
        FFLAS::fflas_delete(ffmat);        chrono.stop();
        std::clog << "[DATABASE] generated, " << chrono << std::endl;
    }

    bool success=true;

        //-------------------------
        // private Protocol
    success &= Protocol<Field,false>(timeinit[0], timeaudit[0], timeserver[0], F, Rand, m, k, DATABASEF_NAME.c_str());

    for(size_t i=0; i<iters; ++i) {
        success &= Protocol<Field,false>(timeinit[i], timeaudit[i], timeserver[i], F, Rand, m, k, DATABASEF_NAME.c_str());
    }

    std::sort(timeinit.begin(),timeinit.end());
    std::sort(timeaudit.begin(),timeaudit.end());
    std::sort(timeserver.begin(),timeserver.end());

    std::clog << (1000.*timeinit[iters/2]) << " ms\t: [SETUP] [PRIVATE] " << k  << " : " << mediandeviation(timeinit) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeserver[iters/2]) << " ms\t: [AUDIT SERVER] [PRIVATE] " << k  << " : " << mediandeviation(timeserver) << "% (" << iters << ')' << std::endl;
    std::clog << (1000.*timeaudit[iters/2]) << " ms\t: [AUDIT CLIENT] [PRIVATE] " << k  << " : " << mediandeviation(timeaudit) << "% (" << iters << ')' << std::endl;

        //-------------------------
        // public Protocol
    success &= Protocol<Field,true>(timeinit[0], timeaudit[0], timeserver[0], F, Rand, m, k, DATABASEF_NAME.c_str());
    for(size_t i=0; i<iters; ++i) {
        success &= Protocol<Field,true>(timeinit[i], timeaudit[i], timeserver[i], F, Rand, m, k, DATABASEF_NAME.c_str());
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
