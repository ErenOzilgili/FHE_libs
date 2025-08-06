#ifndef INNER_SEAL_H
#define INNER_SEAL_H

#include "seal/seal.h"
#include <vector>
#include <memory>

using namespace std;
using namespace seal;

void innerProduct_(shared_ptr<SEALContext> context,
                  PublicKey &public_key,
                    SecretKey &secret_key,
                    RelinKeys &relin_keys,
                    GaloisKeys &galois_keys,

                    CKKSEncoder &encoder,
                    Encryptor &encryptor,
                    Evaluator &evaluator,
                    Decryptor &decryptor,

                    int innerProNo,
                    double scale,
                
                    const vector<double>& input_vec,
                    vector<double>& out_res);

#endif // INNER_SEAL_h