#ifndef MULT_SEAL_H
#define MULT_SEAL_H

#include "seal/seal.h"
#include <vector>
#include <memory>

using namespace std;
using namespace seal;

// Tree-wise addition of ciphertexts (log-depth)
Ciphertext TreewiseSum(Evaluator &evaluator, vector<Ciphertext> &cts);

// Tree-wise addition of ciphertexts (log-depth) (Parallel)
Ciphertext TreewiseSum_(shared_ptr<SEALContext> context, Evaluator &evaluator, vector<Ciphertext> &cts);

// Matrix-vector multiplication using CKKS scheme
vector<double> matrixVectorMul(shared_ptr<SEALContext> context,
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
                     double tolerance);

// Matrix-vector multiplication using CKKS scheme (for parallel use)
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
                     vector<Ciphertext>& results,

                     int rowNo,
                     double scale,
                     int tid,
                     double tolerance);

#endif 
