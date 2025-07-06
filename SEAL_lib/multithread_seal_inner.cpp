#include "examples.h"

using namespace std;
using namespace seal;

/*
double innerProduct(Ciphertext &first, 
                Ciphertext &second,
                PublicKey &public_key,
                SecretKey &secret_key,
                RelinKeys &relin_keys,
                GaloisKeys &galois_keys,
                CKKSEncoder &encoder,
                Evaluator &evaluator,
                Decryptor &decryptor,
                //SlotCount --> Total slot count
                size_t slotCount){
    Ciphertext multiplied;
    Ciphertext rotated;

    //Multiply once and then relinearize to get the slotwise multiplication
    evaluator.multiply(first, second, multiplied);
    evaluator.relinearize_inplace(multiplied, relin_keys);

    Ciphertext result = multiplied; //Copy the multiplied version
    //Rotated now holds the correct multiplication result

    //Now rotate and sum to obtain the inner product result at the first index
    for(int steps = 1; steps <= log2(slotCount); steps *= 2){
        evaluator.rotate_vector(result, steps, galois_keys, rotated);
        evaluator.add_inplace(result, rotated);
    }

    //Now decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);

    vector<double> output_result;
    encoder.decode(plain_result, output_result);

    return output_result[0]; //Inner product accumulated in the first slot
}
*/

void bench(shared_ptr<SEALContext> context,
                  PublicKey public_key,
                    SecretKey secret_key,
                    RelinKeys relin_keys,
                    GaloisKeys galois_keys,
                    double scale,
                    int thread_id,
                    double tolerance){
    /*
    Note that, only the underlying pointer is passed and 
    secret_key, relin_keys, galois_keys, etc. are not copied 
    throughout different threads
    */
    //Each thread uses its own local memory pool:
    auto local_pool = MemoryPoolHandle::New();

    /*
    Below can also be used among different threads if needed
    */
    CKKSEncoder encoder(*context);
    Encryptor encryptor(*context, public_key);
    Evaluator evaluator(*context);
    Decryptor decryptor(*context, secret_key);   

    //Obtain the slot count from the encoder object
    size_t slotCount = encoder.slot_count();

    //Vector which will be passed as the ckks vector
    vector<double> input_vec(slotCount); //Of size polydegree / 2 = slot_count ---- polydegree = N, slot_count = N / 2

    ///////////////////////////////
    // Prepare the input vector 
    ///////////////////////////////
    //inputSlotCount --> Nonzero slot count
    /*
    int inputSlotCount = 10;
    double inputVecSum = 0;
    for(int i = 0; i < inputSlotCount; i++){
        double valuePushed = static_cast<double>((i + 1)) / inputSlotCount;
        input_vec.push_back(valuePushed);
        inputVecSum += valuePushed*valuePushed;
    }
    */
    random_device rd;
    mt19937 rng(rd());
    uniform_real_distribution<double> dist(-5.0, 5.0); 

    for (auto &slot : input_vec)
        slot = dist(rng);

    Plaintext plain;
    encoder.encode(input_vec, scale, plain, local_pool);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted, local_pool);

    //////////////////////////////////////////////////////////////
    // Calculate inner product
    //////////////////////////////////////////////////////////////
    //Call to logRotated inner product 
    //double calcInnerProduct = innerProduct(encrypted, encrypted, public_key, secret_key, relin_keys, galois_keys, encoder, evaluator, decryptor, slotCount);

    Ciphertext multiplied;
    Ciphertext rotated;

    //Multiply once and then relinearize to get the slotwise multiplication
    evaluator.multiply(encrypted, encrypted, multiplied, local_pool);
    evaluator.relinearize_inplace(multiplied, relin_keys, local_pool);

    Ciphertext result = multiplied; //Copy the multiplied version
    //Rotated now holds the correct multiplication result

    //Now rotate and sum to obtain the inner product result at the first index
    for(int steps = 1; steps <= log2(slotCount); steps *= 2){
        evaluator.rotate_vector(result, steps, galois_keys, rotated, local_pool);
        evaluator.add_inplace(result, rotated);
    }

    //Now decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);

    vector<double> output_result;
    encoder.decode(plain_result, output_result, local_pool);
    //Now the output_result[0] holds the result of the inner product.

    /////////////////////////////////////////////
    // Confirm result (If wanted)
    /////////////////////////////////////////////
    //Assert for the confirmation of whether it is done correctly or not
    /*
    if(abs(inputVecSum - calcInnerProduct) > tolerance){
        cout << "Aborted! Threshold not satisfied." << endl;
        abort();
    }
    cout << "Thread no " << thread_id << ": " <<inputVecSum << " - " << calcInnerProduct << endl;
    */

    //cout << "Finished" << endl;
}

int main(){
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));

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

    /*
    CKKSEncoder encoder(*context);
    Encryptor encryptor(*context, public_key);
    Decryptor decryptor(*context, secret_key);
    Evaluator evaluator(*context);
    */   

    double scale = pow(2.0, 40);
    double tolerance = 1e-6; // (10^-6)

    vector<thread> workers;
    int num_worker_initial = 4;
    int num_inner_initial = 4; 

    bool doAcrossThreads = true; //Do in parallel or serial
    /*
    First loop
    */
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

                //Distrubute the work among threads (workers)
                for (int t = 0; t < num_worker; t++) {
                    workers.emplace_back([&, t]() {
                        for (int i = t; i < num_inner; i += num_worker) {
                            bench(context, public_key, secret_key, relin_keys, galois_keys, scale, i, tolerance);
                        }
                    });
                }
                for (auto &t : workers) {
                    t.join();
                }

                //End timer
                auto t_end = chrono::high_resolution_clock::now();

                //Assign elapsed
                elapsed = chrono::duration<double>(t_end - t_start).count();
            }
            else{
                //Start timer
                auto t_start = chrono::high_resolution_clock::now();

                for(int t = 0; t < num_inner; t++){
                    bench(context, public_key, secret_key, relin_keys, galois_keys, scale, -1, tolerance);
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