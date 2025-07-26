#include "openfhe.h"
#include "mult_openFHE.h"

#include <iostream>
#include <vector>
#include <thread>
#include <random>
#include <chrono>
#include <cstdlib>

using namespace lbcrypto;
using namespace std;

int main(){
    ////////////////////////////////////////
    // Setup context
    ////////////////////////////////////////
    CCParams<CryptoContextCKKSRNS> parameters;

    uint32_t ringDim = 8192;
    uint32_t batchSize = ringDim / 2;
    uint32_t dcrtBits = 40;
    double tolerance = 1e-1;

    parameters.SetMultiplicativeDepth(3);
    parameters.SetBatchSize(batchSize); // N / 2 = ringDim / 2 = slotCount
    parameters.SetRingDim(ringDim);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    parameters.SetScalingModSize(dcrtBits); // Bit precision --> Scale

    CryptoContext<DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    /*
    Following the example at (inner product example)
    https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/inner-product.cpp
    */
    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    /*
    We need to give the rotation steps (how many rotations) array to the cryptocontext object priorly
    for Galois keys to be generated
    */
    int steps = 1;
    int totalRotCount = (int)(log2(batchSize));
    vector<int> rotationSteps(totalRotCount);
    for(int i = 0; i < totalRotCount; i++){
        rotationSteps[i] = steps;
        steps *= 2;
    }
    cc->EvalAtIndexKeyGen(keyPair.secretKey, rotationSteps);

    ////////////////////////////////////////
    // Tests
    ////////////////////////////////////////

    int rows = 8;
    int slots = parameters.GetBatchSize();
    int cols = slots;

    // Seed RNG with time and tid
    mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    uniform_real_distribution<double> dist(-1.0, 1.0);

    // Declare matrix (rows x cols)
    vector<vector<double>> mat(rows, vector<double>(cols));

    // Declare vector (size = cols)
    vector<double> vec(cols);

    // Initialize vector with random values in (-1, 1)
    for (int i = 0; i < cols; ++i) {
        vec[i] = dist(rng);
    }

    // Initialize matrix with random values in (-1, 1)
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            mat[i][j] = dist(rng);
        }
    }

    //To hold the results
    vector<Ciphertext<DCRTPoly>> matOut(rows);//Treewise sum to obtain belove multRes
    Ciphertext<DCRTPoly> mulRes;

    ////////////
    /*
    This is done due to below link
    // TODO: link here
    */
    vector<double> dummy(batchSize, 1.0);
    auto dummy_plain = cc->MakeCKKSPackedPlaintext(dummy);
    auto dummy_enc = cc->Encrypt(keyPair.publicKey, dummy_plain);
    auto dummy_eval = cc->EvalMult(dummy_enc, dummy_enc);
    ////////////

    vector<thread> workers;
    int num_worker_initial = 4;

    bool doAcrossThreads = true; //Do in parallel or serial

    for(int k = 0; k < 2; k++){
        matOut.assign(rows, nullptr); //Reinitialize the vector (Needed)

        //Do with 4 and 8 cores
        int num_worker = num_worker_initial * (int)(pow(2.0, k));

        double elapsed = 0;

        if(doAcrossThreads){//If across threads, enter here for benchmark
            workers.clear();
            //Start timer
            auto t_start = chrono::high_resolution_clock::now();

            //Distrubute the work among threads (workers)
            //First, do the multiplication operations rowwise
            for (int t = 0; t < num_worker; t++) {
                workers.emplace_back([&, t]() {
                    for (int i = t; i < rows; i += num_worker) {
                        matrixVectorMul_(cc, keyPair,
                            mat[i], vec, matOut, i, slots, t, tolerance);
                    }
                });
            }
            for (auto &t : workers) {
                t.join();
            }

            cout << "Done rows." << endl;

            //Now, use ciphertexts inside matOut to sum treewise in parallel.
            mulRes = TreewiseSum(cc, matOut);


            // Vector to store the multiplication result
            Plaintext ptRes;
            cc->Decrypt(keyPair.secretKey, mulRes, &ptRes);
            ptRes->SetLength(slots); // Trims the vector to expected length
            vector<complex<double>> vec_res = ptRes->GetCKKSPackedValue();

            //We use real parts snce we passed in real doubles earlier on
            for(int i = 0; i < rows; i++){
                double expVal = 0;

                for(int j = 0; j < cols; j++){
                    expVal += mat[i][j] * vec[j];
                }

                /*
                if(abs(expVal - real(vec_res[i])) > tolerance){
                    std::cout << "Results don't match!" << std::endl;
                    exit(1);
                }
                */

                printf("Expected: %.12f, Found: %.12f\n", expVal, real(vec_res[i]));
            }

            //End timer
            auto t_end = chrono::high_resolution_clock::now();

            //Assign elapsed
            elapsed = chrono::duration<double>(t_end - t_start).count();
        }
        else{
            //Start timer
            auto t_start = chrono::high_resolution_clock::now();

            //SINGLE THREAD
            cout << "TODO: SINGLE THREAD!" << endl;

            //End timer
            auto t_end = chrono::high_resolution_clock::now();

            //Assign elapsed
            elapsed = chrono::duration<double>(t_end - t_start).count();
        }

        //Print the results
        if(doAcrossThreads){
            cout << "All threads finished." << endl;
        }
        else{
            cout << "No threads." << endl;
        }
        cout << "\tTotal time: " << elapsed << "\n\n";  

    }

    return 0;
}