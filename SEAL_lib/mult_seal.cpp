#include "examples.h"
#include "mult_seal.h"

#include <future>

using namespace std;
using namespace seal;

Ciphertext TreewiseSum(Evaluator &evaluator, vector<Ciphertext>& cts){
        if (cts.empty()) {
        throw invalid_argument("Ciphertext vector is empty.");
    }

    vector<Ciphertext>& current = cts;

    while (current.size() > 1) {
        vector<Ciphertext> next;

        for (int i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                // Use the pool of one of the operands (safe assumption)
                MemoryPoolHandle pool = current[i].pool();
                Ciphertext sum(pool);
                evaluator.add(current[i], current[i + 1], sum);
                next.push_back(std::move(sum));
            } else {
                // No ciphertext to be added with, carry 
                next.push_back(std::move(current[i]));
            }
        }

        // Here now alias for next
        current = std::move(next);
    }

    return current[0];
}

Ciphertext TreewiseSum_(shared_ptr<SEALContext> context, Evaluator &evaluator,
                                std::vector<Ciphertext> &cts) {
//size_t min_block_size = 4
    if (cts.empty()) {
        throw std::invalid_argument("Ciphertext vector is empty.");
    }

    while (cts.size() > 1) {
        std::vector<Ciphertext> next;
        size_t n = cts.size();

        std::vector<std::future<Ciphertext>> futures;

        for (size_t i = 0; i < n; i += 2) {
            if (i + 1 < n) {
                // Parallel add: launch async task
                futures.emplace_back(std::async(std::launch::async, [&context](Ciphertext a, Ciphertext b) {
                    // Initialize thread-local pool explicitly
                    Ciphertext sum(*context, MemoryPoolHandle::ThreadLocal());
                    Evaluator evaluator(*context); // Create per-thread evaluator
                    evaluator.add(a, b, sum);
                    return sum;
                }, cts[i], cts[i + 1]));
            } else {
                // Odd one out
                next.push_back(std::move(cts[i]));
            }
        }

        // Collect results from futures
        for (auto &f : futures) {
            next.push_back(f.get());
        }

        // Prepare the net iteration
        cts = std::move(next);
    }

    return cts[0];
}


/*
void matrixVectorMul(shared_ptr<SEALContext> context,
                PublicKey &public_key,
                    SecretKey &secret_key,
                    RelinKeys &relin_keys,
                    GaloisKeys &galois_keys,

                    CKKSEncoder &encoder,
                    Encryptor &encryptor,
                    Evaluator &evaluator,
                    Decryptor &decryptor,

                    int rows,
                    double scale,
                    int tid, 
                    double tolerance){

    //Each thread uses its own local memory pool
    auto local_pool = MemoryPoolHandle::New();

    //Obtain the slot count from the encoder object
    int slots = encoder.slot_count();

    int cols = slots;

    
    mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count() + tid);
    uniform_real_distribution<double> dist(-1.0, 1.0); 

    // Initialize matrix and vecto with random doubles
    vector<vector<double>> mat(rows, vector<double>(cols));
    vector<double> vec(cols);
    for (size_t i = 0; i < cols; i++){
        vec[i] = dist(rng);
    } 
    for (size_t i = 0; i < rows; i++){
        for (size_t j = 0; j < slots; j++){
            mat[i][j] = dist(rng);
        }
    }
    

    // Encrypt matrix rows
    vector<Ciphertext> ctMat(rows);
    for (int i = 0; i < rows; i++) {
        Plaintext pt;
        encoder.encode(mat[i], scale, pt, local_pool);
        encryptor.encrypt(pt, ctMat[i], local_pool);
    }

    // Encrypt vector
    Plaintext ptVec;
    encoder.encode(vec, scale, ptVec, local_pool);
    Ciphertext ctVec;
    encryptor.encrypt(ptVec, ctVec, local_pool);

    // Compute inner products
    vector<Ciphertext> innerResults(rows);

    for (int i = 0; i < rows; i++) {
        // Create one-hot encoded vector to extract the i-th slot
        vector<double> oneHot(slots, 0.0);
        oneHot[i] = 1.0;
        Plaintext ptHot;
        encoder.encode(oneHot, scale, ptHot, local_pool);
        Ciphertext ctHot;
        encryptor.encrypt(ptHot, ctHot, local_pool);

        // Multiply row i with vector
        Ciphertext product;
        evaluator.multiply(ctMat[i], ctVec, product, local_pool);
        evaluator.relinearize_inplace(product, relin_keys, local_pool);
        evaluator.rescale_to_next_inplace(product, local_pool);

        // Inner product via rotations and additions
        Ciphertext res = product;
        for (int step = 1; step < slots; step *= 2) {
            Ciphertext rotated;
            evaluator.rotate_vector(res, step, galois_keys, rotated, local_pool);
            evaluator.add_inplace(res, rotated);
        }


        //Multiply result with one hot vector
        auto res_parms_id = res.parms_id();
        Ciphertext res_;
        // Ensure ctHot matches res's level
        evaluator.mod_switch_to_inplace(ctHot, res.parms_id(), local_pool);
        evaluator.multiply(res, ctHot, res_, local_pool);
        evaluator.relinearize_inplace(res_, relin_keys, local_pool);
        evaluator.rescale_to_next_inplace(res_, local_pool);

        innerResults[i] = res_;
    }

    Ciphertext mulRes = TreewiseSum(evaluator, innerResults);

    // Vector to store the multiplication result
    Plaintext ptRes;
    decryptor.decrypt(mulRes, ptRes);

    vector<double> vec_res(rows);
    encoder.decode(ptRes, vec_res, local_pool);

    for(int i = 0; i < rows; i++){
        double expVal = 0;

        for(int j = 0; j < cols; j++){
            expVal += mat[i][j] * vec[j];
        }

        printf("Expected: %.12f, Found: %.12f\n", expVal, real(vec_res[i]));
    }

}
*/

void matrixVectorMul(shared_ptr<SEALContext> context,
                PublicKey &public_key,
                    SecretKey &secret_key,
                    RelinKeys &relin_keys,
                    GaloisKeys &galois_keys,

                    CKKSEncoder &encoder,
                    Encryptor &encryptor,
                    Evaluator &evaluator,
                    Decryptor &decryptor,

                    vector<vector<double>>& mat,
                    vector<double>& vec,
                    int rows,
                    double scale,
                    int tid, 
                    double tolerance){

    //Each thread uses its own local memory pool
    auto local_pool = MemoryPoolHandle::New();

    //Obtain the slot count from the encoder object
    int slots = encoder.slot_count();

    int cols = slots;

    // Encrypt matrix rows
    vector<Ciphertext> ctMat(rows);
    for (int i = 0; i < rows; i++) {
        Plaintext pt;
        encoder.encode(mat[i], scale, pt, local_pool);
        encryptor.encrypt(pt, ctMat[i], local_pool);
    }

    // Encrypt vector
    Plaintext ptVec;
    encoder.encode(vec, scale, ptVec, local_pool);
    Ciphertext ctVec;
    encryptor.encrypt(ptVec, ctVec, local_pool);

    // Compute inner products
    vector<Ciphertext> innerResults(rows);

    for (int i = 0; i < rows; i++) {
        // Create one-hot encoded vector to extract the i-th slot
        vector<double> oneHot(slots, 0.0);
        oneHot[i] = 1.0;
        Plaintext ptHot;
        encoder.encode(oneHot, scale, ptHot, local_pool);
        Ciphertext ctHot;
        encryptor.encrypt(ptHot, ctHot, local_pool);

        // Multiply row i with vector
        Ciphertext product;
        evaluator.multiply(ctMat[i], ctVec, product, local_pool);
        evaluator.relinearize_inplace(product, relin_keys, local_pool);
        evaluator.rescale_to_next_inplace(product, local_pool);

        // Inner product via rotations and additions
        Ciphertext res = product;
        for (int step = 1; step < slots; step *= 2) {
            Ciphertext rotated;
            evaluator.rotate_vector(res, step, galois_keys, rotated, local_pool);
            evaluator.add_inplace(res, rotated);
        }


        //Multiply result with one hot vector
        auto res_parms_id = res.parms_id();
        Ciphertext res_;
        // Ensure ctHot matches res's level
        evaluator.mod_switch_to_inplace(ctHot, res.parms_id(), local_pool);
        evaluator.multiply(res, ctHot, res_, local_pool);
        evaluator.relinearize_inplace(res_, relin_keys, local_pool);
        evaluator.rescale_to_next_inplace(res_, local_pool);

        innerResults[i] = res_;
    }

    Ciphertext mulRes = TreewiseSum(evaluator, innerResults);

    // Vector to store the multiplication result
    Plaintext ptRes;
    decryptor.decrypt(mulRes, ptRes);

    vector<double> vec_res(rows);
    encoder.decode(ptRes, vec_res, local_pool);

    for(int i = 0; i < rows; i++){
        double expVal = 0;

        for(int j = 0; j < cols; j++){
            expVal += mat[i][j] * vec[j];
        }

        printf("Expected: %.12f, Found: %.12f\n", expVal, real(vec_res[i]));
    }

}

void matrixVectorMul_(shared_ptr<SEALContext> context,
                    PublicKey &public_key,
                    SecretKey &secret_key,
                    RelinKeys &relin_keys,
                    GaloisKeys &galois_keys,

                    CKKSEncoder &encoder,
                    Encryptor &encryptor,
                    Evaluator &evaluator,
                    Decryptor &decryptor,

                    vector<double>& row,
                    vector<double>& vec,
                    vector<Ciphertext>& results, //OUT

                    int rowNo,
                    double scale,
                    int tid, 
                    double tolerance){

    //Each thread uses its own local memory pool
    auto local_pool = MemoryPoolHandle::New();

    //Obtain the slot count from the encoder object
    int slots = encoder.slot_count();

    int cols = slots;
    
    // Encrypt a matrix row
    Ciphertext ctMatRow(local_pool);
    Plaintext pt;
    encoder.encode(row, scale, pt, local_pool);
    encryptor.encrypt(pt, ctMatRow, local_pool);

    // Encrypt vector
    Plaintext ptVec;
    encoder.encode(vec, scale, ptVec, local_pool);
    Ciphertext ctVec(local_pool);
    encryptor.encrypt(ptVec, ctVec, local_pool);

    // Create one-hot encoded vector to extract the i-th slot
    vector<double> oneHot(slots, 0.0);
    oneHot[rowNo] = 1.0;
    Plaintext ptHot;
    encoder.encode(oneHot, scale, ptHot, local_pool);
    Ciphertext ctHot(local_pool);
    encryptor.encrypt(ptHot, ctHot, local_pool);

    // Multiply row i with vector
    Ciphertext product(local_pool);
    evaluator.multiply(ctMatRow, ctVec, product, local_pool);
    evaluator.relinearize_inplace(product, relin_keys, local_pool);
    evaluator.rescale_to_next_inplace(product, local_pool);

    // Inner product via rotations and additions
    Ciphertext res(product, local_pool);
    for (int step = 1; step < slots; step *= 2) {
        Ciphertext rotated(local_pool);
        evaluator.rotate_vector(res, step, galois_keys, rotated, local_pool);
        evaluator.add_inplace(res, rotated);
    }

    //Multiply result with one hot vector
    auto res_parms_id = res.parms_id();
    Ciphertext res_(local_pool);
    // Ensure ctHot matches res's level
    evaluator.mod_switch_to_inplace(ctHot, res.parms_id(), local_pool);
    evaluator.multiply(res, ctHot, res_, local_pool);
    evaluator.relinearize_inplace(res_, relin_keys, local_pool);
    evaluator.rescale_to_next_inplace(res_, local_pool);

    //Record to main ciphertexts vector (No race condition here)
    results[rowNo] = std::move(res_);

    //Treewise
    // TODO: Somehow deal with doing the addition in parallel

    
    //Ciphertext mulRes = TreewiseSum(evaluator, innerResults);

    // Vector to store the multiplication result
    //Plaintext ptRes;
    //decryptor.decrypt(mulRes, ptRes);

    //vector<double> vec_res(rows);
    //encoder.decode(ptRes, vec_res, local_pool);

    

}


/*
void matrixVectorMul_(shared_ptr<SEALContext> context,
                    PublicKey &public_key,
                    SecretKey &secret_key,
                    RelinKeys &relin_keys,
                    GaloisKeys &galois_keys,

                    CKKSEncoder &encoder,
                    Encryptor &encryptor,
                    Evaluator &evaluator,
                    Decryptor &decryptor,

                    vector<double>& row,
                    vector<double>& vec,
                    vector<Ciphertext>& results, //OUT

                    int rowNo,
                    double scale,
                    int tid, 
                    double tolerance){

    //Obtain the slot count from the encoder object
    int slots = encoder.slot_count();

    int cols = slots;
    
    // Encrypt a matrix row
    Ciphertext ctMatRow;
    Plaintext pt;
    encoder.encode(row, scale, pt);
    encryptor.encrypt(pt, ctMatRow);

    // Encrypt vector
    Plaintext ptVec;
    encoder.encode(vec, scale, ptVec);
    Ciphertext ctVec;
    encryptor.encrypt(ptVec, ctVec);

    // Create one-hot encoded vector to extract the i-th slot
    vector<double> oneHot(slots, 0.0);
    oneHot[rowNo] = 1.0;
    Plaintext ptHot;
    encoder.encode(oneHot, scale, ptHot);
    Ciphertext ctHot;
    encryptor.encrypt(ptHot, ctHot);

    // Multiply row i with vector
    Ciphertext product;
    evaluator.multiply(ctMatRow, ctVec, product);
    evaluator.relinearize_inplace(product, relin_keys);
    evaluator.rescale_to_next_inplace(product);

    // Inner product via rotations and additions
    Ciphertext res(product);
    for (int step = 1; step < slots; step *= 2) {
        Ciphertext rotated;
        evaluator.rotate_vector(res, step, galois_keys, rotated);
        evaluator.add_inplace(res, rotated);
    }

    //Multiply result with one hot vector
    auto res_parms_id = res.parms_id();
    Ciphertext res_;
    // Ensure ctHot matches res's level
    evaluator.mod_switch_to_inplace(ctHot, res.parms_id());
    evaluator.multiply(res, ctHot, res_);
    evaluator.relinearize_inplace(res_, relin_keys);
    evaluator.rescale_to_next_inplace(res_);

    //Record to main ciphertexts vector (No race condition here)
    results[rowNo] = res_;

    //Treewise
    // TODO: Somehow deal with doing the addition in parallel

    
    //Ciphertext mulRes = TreewiseSum(evaluator, innerResults);

    // Vector to store the multiplication result
    //Plaintext ptRes;
    //decryptor.decrypt(mulRes, ptRes);

    //vector<double> vec_res(rows);
    //encoder.decode(ptRes, vec_res, local_pool);
}
*/
