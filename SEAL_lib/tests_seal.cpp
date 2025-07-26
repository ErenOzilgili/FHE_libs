#include "examples.h"
#include "mult_seal.h"

using namespace std;
using namespace seal;


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

    CKKSEncoder encoder(*context);
    Encryptor encryptor(*context, public_key);
    Decryptor decryptor(*context, secret_key);
    Evaluator evaluator(*context);  

    double scale = pow(2.0, 40);
    double tolerance = 1e-1; // (10^-1)

    ////////////////////////////////////////
    // Tests
    ////////////////////////////////////////

    // 1) Inner Product
    ////////////////////////////////////////

    // 2) Matrix x Vector Multiplication
    ////////////////////////////////////////
    
    // The dimensionsfor matrix vector multiplication matrix x vector:
    // (rows -by- rows, poly_modulus_degree / 2) x (poly_modulus_degree / 2 -by- 1)
    int rows = 4; 
    int cols = parms.poly_modulus_degree() / 2;
    int slots = cols;

    mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    uniform_real_distribution<double> dist(-1.0, 1.0); 

    // Initialize matrix and vecto with random doubles
    vector<vector<double>> mat(rows, vector<double>(cols));
    vector<double> vec(cols);
    for (size_t i = 0; i < cols; i++){
        vec[i] = dist(rng);
    } 
    for (size_t i = 0; i < rows; i++){
        for (size_t j = 0; j < cols; j++){
            mat[i][j] = dist(rng);
        }
    }

    //To hold the results
    vector<Ciphertext> matOut(rows);//Treewise sum to obtain belove multRes
    Ciphertext mulRes;

    vector<thread> workers;
    int num_worker_initial = 4;

    bool doAcrossThreads = true; //Do in parallel or serial

    for(int k = 0; k < 2; k++){
        matOut = vector<Ciphertext>(rows); //Reinitialize the vector (Needed)

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
                        matrixVectorMul_(context, 
                            ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor), 
                            mat[i], vec, matOut, i, scale, t, tolerance);
              
                    }
                });
            }
            for (auto &t : workers) {
                t.join();
            }

            cout << "Done rows." << endl;

            //Now, use ciphertexts inside matOut to sum treewise in (parallel?) TODO:.
            mulRes = TreewiseSum(evaluator, matOut);

            // Vector to store the multiplication result
            Plaintext ptRes;
            decryptor.decrypt(mulRes, ptRes);

            vector<double> vec_res(rows);
            encoder.decode(ptRes, vec_res);

            for(int i = 0; i < rows; i++){
                double expVal = 0;

                for(int j = 0; j < cols; j++){
                    expVal += mat[i][j] * vec[j];
                }

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

            matrixVectorMul(context, 
                ref(public_key), ref(secret_key), ref(relin_keys), ref(galois_keys), ref(encoder), ref(encryptor), ref(evaluator), ref(decryptor),
                mat, vec, rows, scale, -1, tolerance);

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