#include "openfhe.h"
#include "inner_openFHE.h"

#include <iostream>
#include <vector>
#include <thread>
#include <random>
#include <chrono>
#include <cstdlib>

/*
General guideline from the repo itself for integrating
application level multithreading
https://github.com/openfheorg/openfhe-development/blob/main/docs/static_docs/Best_Performance.md
*/

using namespace lbcrypto;
using namespace std;

void innerProduct(CryptoContext<DCRTPoly>& cc,
           KeyPair<DCRTPoly>& keyPair,
           int innerProNo,
           double tolerance,
           int slotCount,
           const vector<double>& input_vec,
           vector<double>& out_res) {

    auto plain = cc->MakeCKKSPackedPlaintext(input_vec);

    auto encrypted = cc->Encrypt(keyPair.publicKey, plain);

    cc->EvalSquareInPlace(encrypted); //Take a look at here (*)
    cc->RelinearizeInPlace(encrypted);
    cc->RescaleInPlace(encrypted);
    auto result = encrypted;
    
    //Now rotate and sum to obtain the inner product result at the first index
    for (auto steps = 1; steps < slotCount; steps *= 2) {
        auto rotated = cc->EvalAtIndex(result, steps);
        cc->EvalAddInPlace(result, rotated);
    }

    Plaintext plain_result;
    cc->Decrypt(keyPair.secretKey, result, &plain_result);
    plain_result->SetLength(slotCount);

    out_res[innerProNo] = real(plain_result->GetCKKSPackedValue()[0]);
}