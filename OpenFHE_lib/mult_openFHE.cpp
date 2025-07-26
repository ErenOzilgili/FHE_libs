#include "openfhe.h"
#include <iostream>
#include <vector>
#include <thread>
#include <random>
#include <chrono>
#include <cstdlib>

using namespace lbcrypto;
using namespace std;

Ciphertext<DCRTPoly> TreewiseSum(CryptoContext<DCRTPoly>& cc,
                                 std::vector<Ciphertext<DCRTPoly>>& cts) {
    if (cts.empty()) {
        throw invalid_argument("Ciphertext vector is empty.");
    }

    vector<Ciphertext<DCRTPoly>>& current = cts;

    while (current.size() > 1) {
        vector<Ciphertext<DCRTPoly>> next;

        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                // Add pairs
                auto sum = cc->EvalAdd(current[i], current[i + 1]);
                next.push_back(sum);
            } else {
                // Carry forward unmatched ciphertext
                next.push_back(current[i]);
            }
        }

        // Here now alias for next
        current = std::move(next);
    }

    return current[0];
}
Ciphertext<DCRTPoly> TreewiseSum_(CryptoContext<DCRTPoly>& cc,
                                 std::vector<Ciphertext<DCRTPoly>>& cts) {
    if (cts.empty()) {
        throw invalid_argument("Ciphertext vector is empty.");
    }

    vector<Ciphertext<DCRTPoly>>& current = cts;

    while (current.size() > 1) {
        vector<Ciphertext<DCRTPoly>> next;

        for (size_t i = 0; i < current.size(); i += 2) {
            if (i + 1 < current.size()) {
                // Add pairs
                auto sum = cc->EvalAdd(current[i], current[i + 1]);
                next.push_back(sum);
            } else {
                // Carry forward unmatched ciphertext
                next.push_back(current[i]);
            }
        }

        // Here now alias for next
        current = std::move(next);
    }

    return current[0];
}

void matrixVectorMul_(CryptoContext<DCRTPoly> &cc,
           KeyPair<DCRTPoly> &keyPair,

           vector<double>& row,
           vector<double>& vec,
           vector<Ciphertext<DCRTPoly>>& results, //OUT
           int rowNo, int slots, int tid, double tolerance){

    // # of Columns is equal to # of slots 
    int cols = slots;

    //Allocate for encrypted matrix ROW
    Ciphertext<DCRTPoly> ctMatRow;

    //Encode and encrypt the row into ctMatRow
    auto ptRow = cc->MakeCKKSPackedPlaintext(row);
    ctMatRow = cc->Encrypt(keyPair.publicKey, ptRow);

    //Encode and encrypt the vec into ctVec
    Plaintext ptVec = cc->MakeCKKSPackedPlaintext(vec);
    Ciphertext<DCRTPoly> ctVec = cc->Encrypt(keyPair.publicKey, ptVec);

    // Results vector to hold encrypted inner product with one hot encoded version
    Ciphertext<DCRTPoly> innerResult;

    // Create one-hot encoded vector to extract the i-th slot
    vector<double> oneHot(slots, 0.0);
    oneHot[rowNo] = 1.0;
    Plaintext ptHot = cc->MakeCKKSPackedPlaintext(oneHot);
    auto ctHot = cc->Encrypt(keyPair.publicKey, ptHot);

    // Multiply row i with input vector
    auto ctMult = cc->EvalMultAndRelinearize(ctMatRow, ctVec);
    cc->RescaleInPlace(ctMult);

    // Perform log-slots rotation and summation (inner product)
    Ciphertext<DCRTPoly> result = ctMult;
    for (size_t step = 1; step < slots; step *= 2) {
        auto rotated = cc->EvalRotate(result, step);
        cc->EvalAddInPlace(result, rotated);
    }

    // Extract the i-th result
    auto rowRes = cc->EvalMultAndRelinearize(result, ctHot);
    cc->RescaleInPlace(rowRes);

    //Inner result holds the result of the row-wise multiplication
    innerResult = rowRes;

    results[rowNo] = innerResult;

    /*
    // Result of the multiplication after treewise summing
    Ciphertext<DCRTPoly> mulRes = TreewiseSum(cc, innerResults);

    // Vector to store the multiplication result
    Plaintext ptRes;
    cc->Decrypt(keyPair.secretKey, mulRes, &ptRes);
    ptRes->SetLength(slots); // Trims the vector to expected length
    vector<complex<double>> vec_res = ptRes->GetCKKSPackedValue();

    //We use real parts snce we passed in real doubles earlier on
    for(int i = 0; i < rows; i++){
        double expVal = 0;

        for(int j = 0; j < cols; j++){
            expVal += mat[i][j] * vec[j];
        }

        printf("Expected: %.12f, Found: %.12f\n", expVal, real(vec_res[i]));
    }
    */
}

void matrixVectorMul(CryptoContext<DCRTPoly> &cc,
           KeyPair<DCRTPoly> &keyPair,
           int rows, int slots, int tid, double tolerance){

    // # of Columns is equal to # of slots 
    int cols = slots;

    // Seed RNG with time and tid
    mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count() + tid);
    uniform_real_distribution<double> dist(-1.0, 1.0);

    // Declare matrix (rows x cols)
    vector<vector<double>> mat(rows, vector<double>(cols));

    // Declare vector (size = cols)
    vector<double> vec(cols);

    // Initialize vector with random values in (-1, 1)
    for (int i = 0; i < cols; ++i) {
        vec[i] = dist(rng);
    }

    // Initialize matrix with random values in (-1, 1)
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            mat[i][j] = dist(rng);
        }
    }

    //Allocate for encrypted matrix
    vector<Ciphertext<DCRTPoly>> ctMat(rows);

    //Encode and encrypt the mat into ctMat
    for(int i = 0; i < rows; i++){
        auto ptRow = cc->MakeCKKSPackedPlaintext(mat[i]);
        ctMat[i] = cc->Encrypt(keyPair.publicKey, ptRow);
    }

    //Encode and encrypt the vec into ctVec
    Plaintext ptVec = cc->MakeCKKSPackedPlaintext(vec);
    Ciphertext<DCRTPoly> ctVec = cc->Encrypt(keyPair.publicKey, ptVec);

    // Results vector to hold encrypted inner products
    vector<Ciphertext<DCRTPoly>> innerResults(rows);

    for (size_t i = 0; i < rows; i++) {
        // Create one-hot encoded vector to extract the i-th slot
        vector<double> oneHot(slots, 0.0);
        oneHot[i] = 1.0;
        Plaintext ptHot = cc->MakeCKKSPackedPlaintext(oneHot);
        auto ctHot = cc->Encrypt(keyPair.publicKey, ptHot);

        // Multiply row i with input vector
        auto ctMult = cc->EvalMultAndRelinearize(ctMat[i], ctVec);
        cc->RescaleInPlace(ctMult);

        // Perform log-slots rotation and summation (inner product)
        Ciphertext<DCRTPoly> result = ctMult;
        for (size_t step = 1; step < slots; step *= 2) {
            auto rotated = cc->EvalRotate(result, step);
            cc->EvalAddInPlace(result, rotated);
        }

        // Extract the i-th result
        auto rowRes = cc->EvalMultAndRelinearize(result, ctHot);
        cc->RescaleInPlace(rowRes);

        innerResults[i] = rowRes;
    }

    // Result of the multiplication after treewise summing
    Ciphertext<DCRTPoly> mulRes = TreewiseSum(cc, innerResults);

    // Vector to store the multiplication result
    Plaintext ptRes;
    cc->Decrypt(keyPair.secretKey, mulRes, &ptRes);
    ptRes->SetLength(slots); // Trims the vector to expected length
    vector<complex<double>> vec_res = ptRes->GetCKKSPackedValue();

    //We use real parts snce we passed in real doubles earlier on
    for(int i = 0; i < rows; i++){
        double expVal = 0;

        for(int j = 0; j < cols; j++){
            expVal += mat[i][j] * vec[j];
        }

        /*
        if(abs(expVal - real(vec_res[i])) > tolerance){
            std::cout << "Results don't match!" << std::endl;
            exit(1);
        }
        */

        printf("Expected: %.12f, Found: %.12f\n", expVal, real(vec_res[i]));
    }
}