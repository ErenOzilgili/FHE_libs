#ifndef INNER_OPENFHE_h
#define INNER_OPENFHE_h

#include "openfhe.h"
#include <vector>

using namespace lbcrypto;
using namespace std;

void innerProduct(CryptoContext<DCRTPoly>& cc,
           KeyPair<DCRTPoly>& keyPair,
           int innerProNo,
           double tolerance,
           int slotCount,
           const vector<double>& input_vec,
           vector<double>& out_res);

#endif // INNER_OPENFHE_h