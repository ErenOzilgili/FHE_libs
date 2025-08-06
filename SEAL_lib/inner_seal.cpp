#include "examples.h"
#include "inner_seal.h"

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
                    vector<double>& out_res){
    /*
    Note that, only the underlying pointer is passed and 
    secret_key, relin_keys, galois_keys, etc. are not copied 
    throughout different threads
    */
    //Each thread uses its own local memory pool:
    auto local_pool = MemoryPoolHandle::New();

    //Obtain the slot count from the encoder object
    size_t slotCount = encoder.slot_count();

    Plaintext plain;
    encoder.encode(input_vec, scale, plain, local_pool);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted, local_pool);

    //////////////////////////////////////////////////////////////
    // Calculate inner product
    //////////////////////////////////////////////////////////////

    Ciphertext multiplied;
    Ciphertext rotated;

    //Multiply once and then relinearize to get the slotwise multiplication
    evaluator.multiply(encrypted, encrypted, multiplied, local_pool);
    evaluator.relinearize_inplace(multiplied, relin_keys, local_pool);
    evaluator.rescale_to_next_inplace(multiplied, local_pool);

    Ciphertext result = multiplied; //Copy the multiplied version
    //Rotated now holds the correct multiplication result

    //Now rotate and sum to obtain the inner product result at the first index
    for(int steps = 1; steps < slotCount; steps *= 2){
        evaluator.rotate_vector(result, steps, galois_keys, rotated, local_pool);
        evaluator.add_inplace(result, rotated);
    }

    //Now decrypt and decode
    Plaintext plain_result;
    decryptor.decrypt(result, plain_result);

    vector<double> output_result;
    encoder.decode(plain_result, output_result, local_pool);
    //Now the output_result[0] holds the result of the inner product.

    out_res[innerProNo] = output_result[0];
}