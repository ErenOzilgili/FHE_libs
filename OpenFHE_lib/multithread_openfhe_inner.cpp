#include "openfhe.h"
#include <iostream>
#include <vector>
#include <thread>
#include <random>
#include <chrono>

/*
General guideline from the repo itself for integrating
application level multithreading
https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md
*/

using namespace lbcrypto;
using namespace std;

void bench(CryptoContext<DCRTPoly> cc,
           KeyPair<DCRTPoly> keyPair,
           int thread_id,
           double tolerance) {

    size_t slotCount = cc->GetRingDimension() / 2;

    vector<double> input_vec(slotCount);
    double inputVecInnerRes = 0;

    random_device rd;
    mt19937 rng(rd());
    uniform_real_distribution<double> dist(-5.0, 5.0);

    //inputVecInnerRes holds the expected inner product result
    for (auto& slot : input_vec) {
        slot = dist(rng);
        inputVecInnerRes += slot * slot;
    }

    auto plain = cc->MakeCKKSPackedPlaintext(input_vec);

    auto encrypted = cc->Encrypt(keyPair.publicKey, plain);

    //Multiply and Relinearize
    auto multiplied = cc->EvalMultAndRelinearize(encrypted, encrypted);

    auto result = multiplied;

    //Now rotate and sum to obtain the inner product result at the first index
    for (auto steps = 1; steps < slotCount; steps *= 2) {
        auto rotated = cc->EvalAtIndex(result, steps);
        result = cc->EvalAdd(result, rotated);
    }

    Plaintext plain_result;
    cc->Decrypt(keyPair.secretKey, result, &plain_result);
    plain_result->SetLength(slotCount);

    complex<double> finalRes = plain_result->GetCKKSPackedValue()[0];

    if (abs(inputVecInnerRes - real(finalRes)) > tolerance) {
        cout << "Thread " << thread_id << ": MISMATCH! " << inputVecInnerRes << " vs " << real(finalRes) << endl;
        abort();
    }
}

int main() {
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
    // Warm-up
    ////////////////////////////////////////
    /*
    This is done due to below link
    // TODO: link here
    */
    vector<double> dummy(batchSize, 1.0);
    auto dummy_plain = cc->MakeCKKSPackedPlaintext(dummy);
    auto dummy_enc = cc->Encrypt(keyPair.publicKey, dummy_plain);
    auto dummy_eval = cc->EvalMult(dummy_enc, dummy_enc);

    ////////////////////////////////////////
    // Threads
    ////////////////////////////////////////

    //Worker number is set to 4 and 8 (physical - virtual # of cores for my pc specs)
    vector<thread> workers;
    int num_worker_initial = 4;
    int num_inner_initial = 4; //Number of inner products done (different randomly generated ciphertexts)

    bool doAcrossThreads = false; //Do in parallel or serial

    for(int k = 0; k < 2; k++){
        //Do with 4 and 8 cores
        int num_worker = num_worker_initial * (int)(pow(2.0, k));

        for(int j = 0; j < 10; j++){
            int num_inner = num_inner_initial * (int)(pow(2.0, j));

            double elapsed = 0;

            if(doAcrossThreads){//If across threads, enter here for benchmark
                workers.clear();
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                for (int t = 0; t < num_worker; t++) {
                    workers.emplace_back([&, t]() {
                        for (int i = t; i < num_inner; i += num_worker) {
                            bench(cc, keyPair, t, tolerance);
                        }
                    });
                }

                for (auto& t : workers) {
                    t.join();
                }

                auto t_end = chrono::high_resolution_clock::now();
                elapsed = chrono::duration<double>(t_end - t_start).count();
            }
            else{
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                for(int t = 0; t < num_inner; t++){
                    bench(cc, keyPair, -1, tolerance);
                }

                //End timer
                auto t_end = chrono::high_resolution_clock::now();

                //Assign elapsed
                elapsed = chrono::duration<double>(t_end - t_start).count();
            }

            //Print the results
            if(doAcrossThreads){
                cout << "All threads finished." << endl;
                cout << "With " << num_worker << " threads -- On " << num_inner << " ciphertexts, each inner producted with itself." << endl;
            }
            else{
                cout << "No threads." << endl;
                cout << "With " << 0 << " threads -- On " << num_inner << " ciphertexts, each inner producted with itself." << endl;
            }
            cout << "\tTotal time: " << elapsed << "\n\n";  

        }

        cout << "------------------------------------------" << endl;
        cout << "------------------------------------------\n\n";

        if(!doAcrossThreads){
            break;
        }
    }

    return 0;
}
