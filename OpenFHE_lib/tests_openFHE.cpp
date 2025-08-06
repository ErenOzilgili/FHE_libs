#include "openfhe.h"
#include "mult_openFHE.h"
#include "inner_openFHE.h"

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

    /*
    //FLEXIBLEAUTO
    uint32_t ringDim = 8192; //8192
    uint32_t batchSize = ringDim / 2;
    uint32_t dcrtBits = 42;
    double tolerance = 1e-1;

    parameters.SetMultiplicativeDepth(5);
    parameters.SetBatchSize(batchSize); // N / 2 = ringDim / 2 = slotCount
    parameters.SetRingDim(ringDim);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    parameters.SetScalingModSize(dcrtBits); // Bit precision --> Scale
    parameters.SetScalingModSize(43);      // e.g., 90 × 5 = 450 bits total
    parameters.SetFirstModSize(44);
    */


    uint32_t ringDim = 16384; 
    uint32_t batchSize = ringDim / 2;
    double tolerance = 1e-1;

    //192-bit N = 16384
    /*
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(40);      
    parameters.SetFirstModSize(45);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    */

    //192-bit N = 8192
    /*
    parameters.SetBatchSize(batchSize);
    parameters.SetRingDim(ringDim);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(33);      
    parameters.SetFirstModSize(41);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    */

    //128 bit N = 8192
    /*
    parameters.SetBatchSize(4096);
    parameters.SetRingDim(8192);
    parameters.SetMultiplicativeDepth(4);
    parameters.SetScalingModSize(44);      
    parameters.SetFirstModSize(43);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security
    */

    //128-bit N = 16384
    parameters.SetBatchSize(8192);
    parameters.SetRingDim(16384);
    parameters.SetMultiplicativeDepth(8);
    parameters.SetScalingModSize(48);      
    parameters.SetFirstModSize(49);
    parameters.SetSecurityLevel(HEStd_NotSet); // disable security

    CryptoContext<DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    auto params = cc->GetCryptoParameters();
    auto ckksParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(params);
    const auto& elemParams = ckksParams->GetElementParams();
    const auto& moduli = elemParams->GetParams();

    std::cout << "Modulus chain (Q):" << std::endl;
    for (size_t i = 0; i < moduli.size(); ++i) {
        std::cout << "Q[" << i << "] = " << std::log2(static_cast<double>(moduli[i]->GetModulus().ConvertToDouble())) << std::endl;
    }

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

    /*
    This is done due to below link
    // TODO: link here
    */
    vector<double> dummy(batchSize, 1.0);
    auto dummy_plain = cc->MakeCKKSPackedPlaintext(dummy);
    auto dummy_enc = cc->Encrypt(keyPair.publicKey, dummy_plain);
    auto dummy_eval = cc->EvalMult(dummy_enc, dummy_enc);
    ////////////

    // Test-1) Inner Product
    ////////////////////////////////////////

    //Initialize
    ////////
    size_t slotCount = cc->GetRingDimension() / 2;

    vector<double> input_vec(slotCount);
    double inputVecInnerRes = 0;

    random_device rd1;
    mt19937 rng1(rd1());
    uniform_real_distribution<double> dist1(-1.0, 1.0);

    //Initialize the same vector to be used across threads
    //inputVecInnerRes holds the expected inner product result
    for (auto& slot : input_vec) {
        slot = dist1(rng1);
        inputVecInnerRes += slot * slot; //Compare with results to find error percentages
    }
    ///////////

    //Worker number is set to 4 and 8 (physical - virtual # of cores for my pc specs)
    vector<thread> workers1;
    int num_worker_initial1 = 4;
    int num_inner_initial1 = 4; //Number of inner products done

    int iterationCount1 = 2;

    bool doAcrossThreads1 = true; //Do in parallel or serial

    for(int k = 0; k < 0; k++){
        //Do with powers of 2 starting with 4 threads (Single thread if flag is off)
        int num_worker1 = num_worker_initial1 * (int)(pow(2.0, k));

        //Number of inner products in parallel
        for(int j = 2; j < 6; j++){
            int num_inner = num_inner_initial1 * (int)(pow(2.0, j));
            cout << "-- Test Inner Product - "<< num_inner << " inner products in parallel" << endl; 

            double elapsedOverLoops = 0; //Over the iterations, total time

            double min_err_per = 100; //Minimum error percentage over the slots - 100 is reasonable because it will get smaller surely
            double max_err_per = 0; //Maximum error percentage over the slots 

            double min_err_amount = 100;
            double max_err_amount = 0;

            //Number of iterations
            for(int k = 0; k < iterationCount1; k++){
                vector<double> out_res(num_inner); //Record the results

                double elapsed = 0;

                if(doAcrossThreads1){//If across threads, enter here for benchmark
                    workers1.clear();
                    //Start timer
                    auto t_start = chrono::high_resolution_clock::now();

                    for (int t = 0; t < num_worker1; t++) {
                        workers1.emplace_back([&, t]() {
                            for (int i = t; i < num_inner; i += num_worker1) {
                                innerProduct(cc, keyPair, i, tolerance, slotCount, input_vec, out_res);
                            }
                        });
                    }

                    for (auto& t : workers1) {
                        t.join();
                    }

                    auto t_end = chrono::high_resolution_clock::now();
                    elapsed = chrono::duration<double>(t_end - t_start).count();

                    for(int i = 0; i < num_inner; i++){
                        //Error percentages per slot - find max and min
                        double err_per = abs((inputVecInnerRes - out_res[i]) / inputVecInnerRes) * 100;
                        double err_amount = abs(inputVecInnerRes - out_res[i]);

                        if(err_per > max_err_per){
                            max_err_per = err_per;
                            max_err_amount = err_amount;
                        }
                        if(err_per < min_err_per){
                            min_err_per = err_per;
                            min_err_amount = err_amount;
                        }
                    }
                }
                else{
                    //Start timer
                    auto t_start = chrono::high_resolution_clock::now();

                    // TODO: SINGLE THREAD
                    for(int i = 0; i < num_inner; i++){
                        innerProduct(cc, keyPair, i, tolerance, slotCount, input_vec, out_res);
                    }

                    //End timer
                    auto t_end = chrono::high_resolution_clock::now();

                    //Assign elapsed
                    elapsed = chrono::duration<double>(t_end - t_start).count();

                    for(int i = 0; i < num_inner; i++){
                        //Error percentages per slot - find max and min
                        double err_per = abs((inputVecInnerRes - out_res[i]) / inputVecInnerRes) * 100;
                        double err_amount = abs(inputVecInnerRes - out_res[i]);

                        if(err_per > max_err_per){
                            max_err_per = err_per;
                            max_err_amount = err_amount;
                        }
                        if(err_per < min_err_per){
                            min_err_per = err_per;
                            min_err_amount = err_amount;
                        }
                    }
                }

                elapsedOverLoops += elapsed;
            }

            cout << "\tAVERAGE TIME OVER ITERATIONS (" << num_worker1 << " threads): " << elapsedOverLoops / iterationCount1 << " seconds per iteration, total of " << iterationCount1 << " iterations." << endl;
            //Below -- over iterations for a specific number of inner products made 
            cout << "MAXIMUM ERROR PERCENTAGE: " << max_err_per << " with error amount: " << max_err_amount << endl;
            cout << "MINIMUM ERROR PERCENTAGE: " << min_err_per << " with error amount: " << min_err_amount << endl;
        }

        if(!doAcrossThreads1){
            break;
        }
    }

    cout << "\n/////////////////////////\n" << endl;

    // Test-2) Matrix Vector Multiplication
    ////////////////////////////////////////

    ////////////
    /*
    Initialize the matrix and vector
    */
    ////////////////////

    int rows = 64; //Matrix rows
    int slots = parameters.GetBatchSize(); //Slots per ciphertext
    int cols = slots;

    // Seed RNG with time and tid
    mt19937 rng2(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    // Values uniformly distributed between as below
    uniform_real_distribution<double> dist2(-1.0, 1.0);

    // Declare matrix (rows x cols)
    vector<vector<double>> mat(rows, vector<double>(batchSize));

    // Declare vector (size = cols)
    vector<double> vec(cols);

    // Initialize vector with random values 
    for (int i = 0; i < cols; ++i) {
        vec[i] = dist2(rng2);
    }

    // Initialize matrix with random values 
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            mat[i][j] = dist2(rng2);
        }
    }

    //To hold the results
    vector<Ciphertext<DCRTPoly>> matOut(rows);//Treewise sum to obtain below multRes
    Ciphertext<DCRTPoly> mulRes;
    /////////////////////

    vector<thread> workers2;
    int num_worker_initial2 = 4;

    bool doAcrossThreads2 = true; //Do in parallel or serial
    int iterationCount2 = 2;

    cout << "\n-- Test Matrix Vector Multiplication - Matrix size --> " << rows << " x " << slots << " - Vector size --> " << slots << " x 1" << endl;

    for(int k = 0; k < 4; k++){
        //Do with powers of 2 starting with 4 threads (Single thread if flag is off)
        int num_worker2 = doAcrossThreads2 ? num_worker_initial2 * (int)(pow(2.0, k)) : 1;

        double elapsedOverLoops = 0; //Over the iterations, total time
        double elapsedTreeWise = 0;

        double min_err_per = 100; //Minimum error percentage over the slots - 100 is reasonable because it will get smaller surely
        double max_err_per = 0; //Maximum error percentage over the slots 

        double min_err_amount = 100;
        double max_err_amount = 0;

        for(int i = 0; i < iterationCount2; i++){
            matOut.assign(rows, nullptr); //Reinitialize the vector (Needed to avoid segmentation fault)

            double elapsed = 0; //Per iteration time

            if(doAcrossThreads2){//If across threads, enter here for benchmark
                workers2.clear();
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                //Distrubute the work among threads (workers)
                //First, do the multiplication operations rowwise
                for (int t = 0; t < num_worker2; t++) {
                    workers2.emplace_back([&, t]() {
                        for (int i = t; i < rows; i += num_worker2) {
                            matrixVectorMul_(cc, keyPair,
                                mat[i], vec, matOut, i, slots, t, tolerance);
                        }
                    });
                }
                for (auto &t : workers2) {
                    t.join();
                }

                auto t_start_tree = chrono::high_resolution_clock::now();
                //Now, use ciphertexts inside matOut to sum treewise in parallel.
                mulRes = TreewiseSum(cc, matOut);
                auto t_end_tree = chrono::high_resolution_clock::now();

                // Vector to store the multiplication result
                Plaintext ptRes;
                cc->Decrypt(keyPair.secretKey, mulRes, &ptRes);
                ptRes->SetLength(slots); // Trims the vector to expected length
                vector<complex<double>> vec_res = ptRes->GetCKKSPackedValue();

                //End timer
                auto t_end = chrono::high_resolution_clock::now();

                //Assign elapsed
                elapsed = chrono::duration<double>(t_end - t_start).count();
                elapsedTreeWise += chrono::duration<double>(t_end_tree - t_start_tree).count();

                //We use real parts snce we passed in real doubles earlier on
                for(int i = 0; i < rows; i++){
                    //Expected value of the multiplication, rowwise
                    double expVal = 0;

                    for(int j = 0; j < cols; j++){
                        expVal += mat[i][j] * vec[j];
                    }

                    //Error percentages per slot - find max and min
                    double err_per = abs((expVal - real(vec_res[i])) / expVal) * 100;
                    double err_amount = abs(expVal - real(vec_res[i]));
                    if(err_per > max_err_per){
                        max_err_per = err_per;
                        max_err_amount = err_amount;
                    }
                    if(err_per < min_err_per){
                        min_err_per = err_per;
                        min_err_amount = err_amount;
                    }
                }
            }
            else{
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                //SINGLE THREAD
                //cout << "TODO: SINGLE THREAD!" << endl;

                //End timer
                auto t_end = chrono::high_resolution_clock::now();

                //Assign elapsed
                elapsed = chrono::duration<double>(t_end - t_start).count();
            }

            elapsedOverLoops += elapsed;
        }
        cout << "\tAVERAGE TIME OVER ITERATIONS (" << num_worker2 << " threads): " << elapsedOverLoops / iterationCount2 << " seconds per iteration, total of " << iterationCount2 << " iterations." << endl; 
        cout << "MAXIMUM ERROR PERCENTAGE: " << max_err_per << " with error amount: " << max_err_amount << endl;
        cout << "MINIMUM ERROR PERCENTAGE: " << min_err_per << " with error amount: " << min_err_amount << endl;

        if(!doAcrossThreads2){
            break;
        }
    }

    return 0;
}