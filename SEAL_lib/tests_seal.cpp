#include "examples.h"
#include "mult_seal.h"
#include "inner_seal.h"

using namespace std;
using namespace seal;


int main(){
    //////////////////////////////
	// SETUP
	//////////////////////////////

    /////////////////////////////////
    // 192-bit Security Params
    /////////////////////////////////

    /*
    int poly_modulus_degree = 1 << 13;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {41, 33, 33 ,33}));
    //Scale = 2^32
    */

    int poly_modulus_degree = 1 << 14;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {45, 40, 40 ,40, 40, 40, 40}));
    //Scale = 2^40

    /////////////////////////////////
    // 128-bit Security Params
    /////////////////////////////////
    /*
    int poly_modulus_degree = 1 << 13;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    */
    //scale = 2^42;
    /*
        Coefficient modulus primes:
        8796092858369 (bit-length: 43)
        8796092792833 (bit-length: 43)
        17592186028033 (bit-length: 44)
        17592185438209 (bit-length: 44)
        17592184717313 (bit-length: 44)
    */

    /*
    int poly_modulus_degree = 1 << 14;
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    //scale = 2^47;
    */
    /*
        Coefficient modulus primes:
        281474976546817 (bit-length: 48)
        281474976317441 (bit-length: 48)
        281474975662081 (bit-length: 48)
        562949952798721 (bit-length: 49)
        562949952700417 (bit-length: 49)
        562949952274433 (bit-length: 49)
        562949951979521 (bit-length: 49)
        562949951881217 (bit-length: 49)
        562949951619073 (bit-length: 49)
    */

    //Scale Value
    double scale = pow(2.0, 40);
    double tolerance = 1e-1; // (10^-1)


    // Print the primes in the coeff_modulus
    cout << "Coefficient modulus primes:" << endl;
    for (const auto& prime : parms.coeff_modulus()) {
        cout << prime.value() << " (bit-length: " << prime.bit_count() << ")" << endl;
    }

    //SEALContext context(parms);
    //auto context = SEALContext::Create(parms);
    auto context = make_shared<SEALContext>(parms);

    KeyGenerator keygen(*context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    CKKSEncoder encoder(*context);
    Encryptor encryptor(*context, public_key);
    Decryptor decryptor(*context, secret_key);
    Evaluator evaluator(*context);  

    ////////////////////////////////////////
    // Tests
    ////////////////////////////////////////

    // 1) Inner Product
    ////////////////////////////////////////
    //Initialize
    ////////
    //Obtain the slot count from the encoder object
    int slotCount = encoder.slot_count();
    vector<double> input_vec(slotCount); //Of size polydegree / 2 = slot_count ---- polydegree = N, slot_count = N / 2

    double inputVecInnerRes = 0; //Hold the sum of the slots

    random_device rd1;
    mt19937 rng1(rd1());
    uniform_real_distribution<double> dist1(-1.0, 1.0); 

    for (auto &slot : input_vec){
        slot = dist1(rng1);
        inputVecInnerRes += (slot * slot);
    }

    vector<thread> workers1;
    int num_worker_initial1 = 4;
    int num_inner_initial1 = 4; //Number of inner products done (different randomly generated ciphertexts)

    int iterationCount1 = 2;

    bool doAcrossThreads1 = true; //Do in parallel or serial

    for(int k = 0; k < 0; k++){
        //Do with 4 and 8 cores
        int num_worker1 = num_worker_initial1 * (int)(pow(2.0, k));

        for(int j = 2; j < 6; j++){
            int num_inner = num_inner_initial1 * (int)(pow(2.0, j));
            cout << "-- Test Inner Product - "<< num_inner << " inner products in parallel" << endl; 

            double elapsedOverLoops = 0; //Over the iterations, total time

            double min_err_per = 100; //Minimum error percentage over the slots - 100 is reasonable because it will get smaller surely
            double max_err_per = 0; //Maximum error percentage over the slots 

            double min_err_amount = 100;
            double max_err_amount = 0;

            for(int l = 0; l < iterationCount1; l++){
                vector<double> out_res(num_inner); //Record the results

                double elapsed = 0;

                if(doAcrossThreads1){//If across threads, enter here for benchmark
                    workers1.clear();
                    //Start timer
                    auto t_start = chrono::high_resolution_clock::now();

                    //Distrubute the work among threads (workers)
                    for (int t = 0; t < num_worker1; t++) {
                        workers1.emplace_back([&, t]() {
                            for (int i = t; i < num_inner; i += num_worker1) {
                                innerProduct_(context, ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor), i, scale, input_vec, out_res);
                            }
                        });
                    }
                    for (auto &t : workers1) {
                        t.join();
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
                else{
                    //Start timer
                    auto t_start = chrono::high_resolution_clock::now();

                    for(int t = 0; t < num_inner; t++){
                        innerProduct_(context, ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor), t, scale, input_vec, out_res);
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

    // 2) Matrix x Vector Multiplication
    ////////////////////////////////////////
    
    // The dimensionsfor matrix vector multiplication matrix x vector:
    // (rows -by- rows, poly_modulus_degree / 2) x (poly_modulus_degree / 2 -by- 1)
    int rows = 32; 
    int cols = parms.poly_modulus_degree() / 2;
    int slots = cols;

    mt19937 rng2(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    uniform_real_distribution<double> dist2(-1.0, 1.0); 

    // Initialize matrix and vecto with random doubles
    vector<vector<double>> mat(rows, vector<double>(cols));
    vector<double> vec(cols);
    for (size_t i = 0; i < cols; i++){
        vec[i] = dist2(rng2);
    } 
    for (size_t i = 0; i < rows; i++){
        for (size_t j = 0; j < cols; j++){
            mat[i][j] = dist2(rng2);
        }
    }

    //To hold the results
    vector<Ciphertext> matOut(rows);//Treewise sum to obtain below multRes
    Ciphertext mulRes;

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
            matOut = vector<Ciphertext>(rows); //Reinitialize the vector (Needed)

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
                            matrixVectorMul_(context, 
                                ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor), 
                                mat[i], vec, matOut, i, scale, t, tolerance);
                
                        }
                    });
                }
                for (auto &t : workers2) {
                    t.join();
                }


                auto t_start_tree = chrono::high_resolution_clock::now();
                //Now, use ciphertexts inside matOut to sum treewise in (parallel?) TODO:.
                mulRes = TreewiseSum(evaluator, matOut);
                auto t_end_tree = chrono::high_resolution_clock::now();

                // Vector to store the multiplication result
                Plaintext ptRes;
                decryptor.decrypt(mulRes, ptRes);

                vector<double> vec_res(rows);
                encoder.decode(ptRes, vec_res);

                //End timer
                auto t_end = chrono::high_resolution_clock::now();

                //Assign elapsed
                elapsed = chrono::duration<double>(t_end - t_start).count();
                elapsedTreeWise += chrono::duration<double>(t_end_tree - t_start_tree).count();

                for(int i = 0; i < rows; i++){
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
                vector<double> vec_res(rows);
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                //SINGLE THREAD
                vec_res = matrixVectorMul(context, 
                    ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor),
                    mat, vec, rows, scale, -1, tolerance);

                for(int i = 0; i < rows; i++){
                    double expVal = 0;

                    for(int j = 0; j < cols; j++){
                        expVal += mat[i][j] * vec[j];
                    }

                    //Error percentages per slot - find max and min
                    double err_per = abs((expVal - vec_res[i]) / expVal) * 100;
                    double err_amount = abs(expVal - vec_res[i]);
                    if(err_per > max_err_per){
                        max_err_per = err_per;
                        max_err_amount = err_amount;
                    }
                    if(err_per < min_err_per){
                        min_err_per = err_per;
                        min_err_amount = err_amount;
                    }
                }

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
        cout << "Elapsed Treewise: " << elapsedTreeWise / iterationCount2 << "seconds." << endl;

        if(!doAcrossThreads2){
            break;
        }

    }

    return 0;
}