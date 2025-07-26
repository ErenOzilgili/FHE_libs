#ifndef MULT_OPENFHE_h
#define MULT_OPENFHE_h

#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using namespace std;

// Treewise summation of ciphertexts
Ciphertext<DCRTPoly> TreewiseSum(CryptoContext<DCRTPoly>& cc,
                                 std::vector<Ciphertext<DCRTPoly>>& cts);

// (Optional) Second version, identical for now
Ciphertext<DCRTPoly> TreewiseSum_(CryptoContext<DCRTPoly>& cc,
                                  std::vector<Ciphertext<DCRTPoly>>& cts);

// Matrix-vector multiplication over CKKS-encrypted data
void matrixVectorMul(CryptoContext<DCRTPoly>& cc,
                     KeyPair<DCRTPoly>& keyPair,
                     int rows,
                     int slots,
                     int tid,
                     double tolerance);

// Matrix-vector multiplication over CKKS-encrypted data (parallel)
void matrixVectorMul_(CryptoContext<DCRTPoly> &cc,
           KeyPair<DCRTPoly> &keyPair,

           vector<double>& row,
           vector<double>& vec,
           vector<Ciphertext<DCRTPoly>>& results, 
           int rowNo, int slots, int tid, double tolerance);

#endif // MULT_OPENFHE_h