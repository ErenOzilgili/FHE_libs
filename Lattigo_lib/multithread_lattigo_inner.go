package main

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// ///////////////////////
// Inner product
// ///////////////////////
func innerProduct_(params ckks.Parameters, enc rlwe.Encryptor, dec rlwe.Decryptor, eval ckks.Evaluator, encoder ckks.Encoder,
	slots int, innerProNo int, vec []float64, vec_out []float64) {
	/*
		// Generate random vector
		vec := make([]float64, slots)
		var expected float64
		r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(tid)))
		for i := range vec {
			val := 10 * (r.Float64() - 0.5)
			vec[i] = val
			expected += val * val
		}
	*/

	// Encode
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(vec, pt); err != nil {
		panic(err)
	}

	// Encrypt
	ct, err := enc.EncryptNew(pt)
	if err != nil {
		panic(err)
	}

	// Square and relinearize
	sq, err := eval.MulRelinNew(ct, ct)
	if err != nil {
		panic(err)
	}
	//Rescale the result
	result := ckks.NewCiphertext(params, 1, sq.Level()-1)
	eval.Rescale(sq, result)

	//Ciphertext for holding the rotations
	rotated := result.CopyNew()

	//Calculate inner product result at the [0] with log rotations and sums
	for i := 1; i < slots; i *= 2 {
		if err := eval.Rotate(result, i, rotated); err != nil {
			panic(err)
		}
		if err := eval.Add(result, rotated, result); err != nil {
			panic(err)
		}
	}

	// Decrypt
	vecRes := make([]float64, slots)
	pt_res := ckks.NewPlaintext(params, result.Level())
	dec.Decrypt(result, pt_res)
	if err := encoder.Decode(pt_res, vecRes); err != nil {
		panic(err)
	}

	vec_out[innerProNo] = vecRes[0]
}

/*
func InnerProduct_test() {
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            13,
		LogQ:            []int{60, 40, 40, 60},
		LogP:            []int{61},
		LogDefaultScale: 40,
	})
	if err != nil {
		panic(err)
	}
	logSlots := params.LogMaxSlots()
	slots := 1 << logSlots
	//scale := params.DefaultScale().Value

	//Generate the keys according to the params
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)
	//Generate rotation keys
	rotations := make([]uint64, 0)
	for i := 1; i < slots; i *= 2 {
		rotations = append(rotations, params.GaloisElement(i))
	}
	gk := kgen.GenGaloisKeysNew(rotations, sk)

	enc := rlwe.NewEncryptor(params, pk)
	dec := rlwe.NewDecryptor(params, sk)
	eval := ckks.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(rlk, gk...))
	encoder := ckks.NewEncoder(params)

	tolerance := 1.0 //CHANGE THIS MECHANISM
	doParallel := true
	numWorkerInitial := 4
	numInnerInitial := 4

	var numWorker int
	var numInner int

	for k := 0; k < 4; k++ {
		//Do with 4 and 8 cores
		numWorker = numWorkerInitial * int(math.Pow(2.0, float64(k)))

		for j := 2; j < 6; j++ {
			numInner = numInnerInitial * int(math.Pow(2.0, float64(j)))

			//Start the timer before distributing into goroutines
			start := time.Now()

			if doParallel {
				var wg sync.WaitGroup
				for w := 0; w < numWorker; w++ {
					wg.Add(1)
					go func(wid int) {
						defer wg.Done()

						// Safe shallow copies for this goroutine
						encoderSh := encoder.ShallowCopy()
						encSh := enc.ShallowCopy()
						decSh := dec.ShallowCopy()
						evalSh := eval.ShallowCopy()

						for i := wid; i < numInner; i += numWorker {
							innerProduct(params, *encSh, *decSh, *evalSh, *encoderSh, slots, wid, tolerance)
						}
					}(w)
				}
				wg.Wait()
			} else {
				for i := 0; i < numInner; i++ {
					innerProduct(params, *enc, *dec, *eval, *encoder, slots, -1, tolerance)
				}
			}

			//Elapsed time
			elapsed := time.Since(start)

			//Print the results
			if doParallel {
				fmt.Printf("All threads finished.\n")
				fmt.Printf("With %d threads -- On %d ciphertexts, each inner producted with itself.\n", numWorker, numInner)
			} else {
				fmt.Printf("No threads.\n")
				fmt.Printf("With 0 threads -- On %d ciphertexts, each inner producted with itself.\n", numInner)
			}
			fmt.Printf("\tTotal time : %f\n\n", elapsed.Seconds())

		}

		fmt.Printf("--------------------------------\n")
		fmt.Printf("--------------------------------\n\n")

		//If not done in parallel, end here and do not test with 8 cores
		if !doParallel {
			break
		}

	}
}
*/

// ////////////////////
// Matrix x Vector
// ////////////////////
func matrixVectorMul(rows int, slots int, params ckks.Parameters, enc rlwe.Encryptor, dec rlwe.Decryptor,
	eval ckks.Evaluator, encoder ckks.Encoder, tid int) []float64 {

	//Column number = slots
	cols := slots
	//Use to generate random floats
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(tid)))

	//Decleare the matrix, rows number of rows
	mat := make([][]float64, rows)
	//Decleare the vector
	vec := make([]float64, cols)

	//Initialize the vector with random floats in (-1, 1)
	for i := 0; i < cols; i++ {
		valV := 2 * (r.Float64() - 0.5)
		vec[i] = valV
	}

	//Initialize matrice with the values
	for i := 0; i < rows; i++ {
		//Allocate for every row
		mat[i] = make([]float64, cols)

		for j := 0; j < cols; j++ {
			//Initialize the matrix with random vectors
			valM := 2 * (r.Float64() - 0.5)
			mat[i][j] = valM
		}
	}

	//Turn float matrix into rlwe Ciphertexts
	ctMat := make([]*rlwe.Ciphertext, rows)

	var err error
	for j := 0; j < rows; j++ {
		ctRow := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(mat[j], ctRow); err != nil {
			panic(err)
		}

		//Now encrypt the row
		ctMat[j], err = enc.EncryptNew(ctRow)
		if err != nil {
			panic(err)
		}
	}

	//Encode and Encrypt the vector ----
	//Encode vec into plaintext (pt)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(vec, pt); err != nil {
		panic(err)
	}

	//ciphertextVector (ctVec)
	ctVec, err := enc.EncryptNew(pt)
	if err != nil {
		panic(err)
	}

	//Now do the multiplication -----
	// innerResults matrix holds the inner products
	// One hot encoded vectors to extract the inner products in desired slots
	innerResults := make([]*rlwe.Ciphertext, rows)

	//Place the inner results in one hot encoded manner inside innerResults[]
	for i := 0; i < rows; i++ {
		oneHotVec := make([]float64, cols)
		oneHotVec[i] = 1.0 //Rest is zero for one hot encoded vector, now turn this into ciphertext
		ptHot := ckks.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(oneHotVec, ptHot); err != nil {
			panic(err)
		}
		ctHot, err := enc.EncryptNew(ptHot)
		if err != nil {
			panic(err)
		}

		//Multiply before log rotations and summation
		mult, err := eval.MulRelinNew(ctMat[i], ctVec)
		if err != nil {
			panic(err)
		}
		//Rescale
		result := ckks.NewCiphertext(params, 1, mult.Level()-1) //This will hold the result of the inner product in its slots
		if err := eval.Rescale(mult, result); err != nil {
			panic(err)
		}

		//Now calculate the inner product of ctMat[i], ctHot using mult
		rotated := result.CopyNew()

		//Calculate inner product result at the [0] with log rotations and sums
		for i := 1; i < slots; i *= 2 {
			if err := eval.Rotate(result, i, rotated); err != nil {
				panic(err)
			}
			if err := eval.Add(result, rotated, result); err != nil {
				panic(err)
			}
		}

		//Now extract the i th position with one hot encoded vector
		rowRes, err := eval.MulRelinNew(result, ctHot)
		if err != nil {
			panic(err)
		}
		rowRes_ := ckks.NewCiphertext(params, 1, rowRes.Level()-1)
		if err := eval.Rescale(rowRes, rowRes_); err != nil {
			panic(err)
		}

		innerResults[i] = rowRes_
	}

	//Now do the treewise summation
	//Multiplication Result
	mulRes, err := TreewiseSum(&eval, innerResults)
	if err != nil {
		fmt.Println(mulRes.Level())
		panic(err)
	}

	//Decode and Decrypt
	vec_res := make([]float64, rows)

	pt_res := ckks.NewPlaintext(params, mulRes.Level())
	dec.Decrypt(mulRes, pt_res)
	if err := encoder.Decode(pt_res, vec_res); err != nil {
		panic(err)
	}

	return vec_res
}

func MatrixVectorMul_(params ckks.Parameters, enc rlwe.Encryptor,
	dec rlwe.Decryptor,
	eval ckks.Evaluator, encoder ckks.Encoder,

	results []*rlwe.Ciphertext, row []float64, vec []float64,
	rowNo int, slots int,
	tid int, tolerance float64) {

	//Column number = slots
	//cols := slots

	//Row Ciphertexts
	var ctMatRow *rlwe.Ciphertext

	var err error
	ctRow := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(row, ctRow); err != nil {
		panic(err)
	}
	//Now encrypt the row
	ctMatRow, err = enc.EncryptNew(ctRow)
	if err != nil {
		panic(err)
	}

	//Encode and Encrypt the vector ----
	//Encode vec into plaintext (pt)
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(vec, pt); err != nil {
		panic(err)
	}
	//ciphertextVector (ctVec)
	ctVec, err := enc.EncryptNew(pt)
	if err != nil {
		panic(err)
	}

	//Now do the multiplication -----
	// innerResults matrix holds the inner products
	// One hot encoded vectors to extract the inner products in desired slots
	var innerResult *rlwe.Ciphertext

	//Place the inner product result in one hot encoded manner
	oneHotVec := make([]float64, slots)
	oneHotVec[rowNo] = 1.0 //Rest is zero for one hot encoded vector, now turn this into ciphertext
	ptHot := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(oneHotVec, ptHot); err != nil {
		panic(err)
	}
	ctHot, err := enc.EncryptNew(ptHot)
	if err != nil {
		panic(err)
	}

	//Multiply before log rotations and summation
	mult, err := eval.MulRelinNew(ctMatRow, ctVec)
	if err != nil {
		panic(err)
	}
	//Rescale
	result := ckks.NewCiphertext(params, 1, mult.Level()-1) //This will hold the result of the inner product in its slots
	if err := eval.Rescale(mult, result); err != nil {
		panic(err)
	}

	//Now calculate the inner product of ctMatRow, ctHot using mult

	rotated := result.CopyNew()

	//Calculate inner product result with log rotations and sums
	for i := 1; i < slots; i *= 2 {
		if err := eval.Rotate(result, i, rotated); err != nil {
			panic(err)
		}
		if err := eval.Add(result, rotated, result); err != nil {
			panic(err)
		}
	}

	//Now extract the i th position with one hot encoded vector
	rowRes, err := eval.MulRelinNew(result, ctHot)
	if err != nil {
		panic(err)
	}
	rowRes_ := ckks.NewCiphertext(params, 1, rowRes.Level()-1)
	if err := eval.Rescale(rowRes, rowRes_); err != nil {
		panic(err)
	}

	innerResult = rowRes_

	results[rowNo] = innerResult

	/*
		//Now do the treewise summation
		//Multiplication Result
		mulRes, err := treewiseSum(&eval, innerResults)
		if err != nil {
			fmt.Println(mulRes.Level())
			panic(err)
		}

		//Decode and Decrypt
		vec_res := make([]float64, rows)

		pt_res := ckks.NewPlaintext(params, mulRes.Level())
		dec.Decrypt(mulRes, pt_res)
		if err := encoder.Decode(pt_res, vec_res); err != nil {
			panic(err)
		}

		for i := 0; i < rows; i++ {

			expVal := 0.0
			for j := 0; j < cols; j++ {
				expVal += mat[i][j] * vec[j]
			}

			//fmt.Println(math.Abs(expVal - vec_res[i]))
			fmt.Printf("Expected: %.6f, Found: %.6f\n", expVal, vec_res[i])
		}
	*/
}

func TreewiseSum(eval *ckks.Evaluator, cts []*rlwe.Ciphertext) (*rlwe.Ciphertext, error) {
	if len(cts) == 0 {
		return nil, errors.New("empty ciphertext slice")
	}

	for len(cts) > 1 {
		var nextLevel []*rlwe.Ciphertext

		for i := 0; i < len(cts); i += 2 {
			if i+1 < len(cts) {
				// Add pairs
				sum, err := eval.AddNew(cts[i], cts[i+1])
				if err != nil {
					return nil, err
				}
				nextLevel = append(nextLevel, sum)
			} else {
				// This element has no match for binary sum, carry to next level
				nextLevel = append(nextLevel, cts[i])
			}
		}

		cts = nextLevel
	}

	return cts[0], nil
}
