package main

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {

	//////////////////////////////
	// SETUP
	//////////////////////////////

	//128 bit - N = 8192
	/*
		params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            13,
			LogQ:            []int{43, 43, 44, 44},
			LogP:            []int{44},
			LogDefaultScale: 42,
		})
	*/

	//128 bit - N = 16384
	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{48, 48, 48, 49, 49, 49, 49, 49},
		LogP:            []int{49},
		LogDefaultScale: 47,
	})

	//192 bit - N = 8192
	/*
		params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            13,
			LogQ:            []int{41, 33, 33},
			LogP:            []int{33},
			LogDefaultScale: 32,
		})
	*/

	/*
		//192 bit - N = 16384
		params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            14,
			LogQ:            []int{45, 40, 40, 40, 40, 40},
			LogP:            []int{40},
			LogDefaultScale: 32,
		})
	*/

	if err != nil {
		panic(err)
	}
	logSlots := params.LogMaxSlots()
	slots := 1 << logSlots
	fmt.Println("Slot count: ", slots)
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

	//////////////////////////////
	// Tests
	//////////////////////////////

	// 1) Inner Product
	////////////////////////////////////////

	// Generate random vector
	vecIn := make([]float64, slots)
	inputVecInnerRes := 0.0
	//Use to generate random floats
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range vecIn {
		val := 10 * (r.Float64() - 0.5)
		vecIn[i] = val
		inputVecInnerRes += val * val
	}

	tolerance := 1.0
	doParallel := true
	numWorkerInitial := 4
	numInnerInitial := 4
	iterationCount := 2

	for k := 0; k < 4; k++ {
		numWorker := numWorkerInitial * int(math.Pow(2.0, float64(k)))

		for j := 2; j < 6; j++ {
			numInner := numInnerInitial * int(math.Pow(2.0, float64(j)))

			fmt.Printf("-- Test Inner Product - %d inner products in parallel\n", numInner)

			var elapsedOverLoops float64
			minErrPer := 100.0
			maxErrPer := 0.0
			minErrAmount := 100.0
			maxErrAmount := 0.0

			for l := 0; l < iterationCount; l++ {
				vec_out := make([]float64, numInner)

				start := time.Now()

				if doParallel {
					var wg sync.WaitGroup
					for w := 0; w < numWorker; w++ {
						wg.Add(1)
						go func(wid int) {
							defer wg.Done()

							encoderSh := encoder.ShallowCopy()
							encSh := enc.ShallowCopy()
							decSh := dec.ShallowCopy()
							evalSh := eval.ShallowCopy()

							for i := wid; i < numInner; i += numWorker {
								innerProduct_(
									params, *encSh, *decSh, *evalSh, *encoderSh,
									slots, i, vecIn, vec_out,
								)
							}
						}(w)
					}
					wg.Wait()
				} else {
					for i := 0; i < numInner; i++ {
						innerProduct_(
							params, *enc, *dec, *eval, *encoder,
							slots, i, vecIn, vec_out,
						)
					}
				}

				elapsed := time.Since(start).Seconds()
				elapsedOverLoops += elapsed

				for i := 0; i < numInner; i++ {
					errPer := math.Abs((inputVecInnerRes - vec_out[i]) / inputVecInnerRes * 100)
					errAmount := math.Abs(inputVecInnerRes - vec_out[i])

					if errPer > maxErrPer {
						maxErrPer = errPer
						maxErrAmount = errAmount
					}
					if errPer < minErrPer {
						minErrPer = errPer
						minErrAmount = errAmount
					}
				}
			}

			fmt.Printf("\tAVERAGE TIME OVER ITERATIONS (%d threads): %f seconds per iteration, total of %d iterations.\n",
				numWorker, elapsedOverLoops/float64(iterationCount), iterationCount)
			fmt.Printf("MAXIMUM ERROR PERCENTAGE: %e with error amount: %e\n", maxErrPer, maxErrAmount)
			fmt.Printf("MINIMUM ERROR PERCENTAGE: %e with error amount: %e\n\n", minErrPer, minErrAmount)
		}

		if !doParallel {
			break
		}
	}

	// 2) Matrix x Vector Multiplication
	////////////////////////////////////////

	// The dimensionsfor matrix vector multiplication matrix x vector:
	// (rows -by- rows, poly_modulus_degree / 2) x (poly_modulus_degree / 2 -by- 1)
	rows := 16
	cols := params.MaxSlots()
	fmt.Println(cols)

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

	// FOr thread to record their respective results
	results := make([]*rlwe.Ciphertext, rows)

	doParallel2 := true
	numWorkerInitial2 := 4

	iterationCount2 := 2
	var numWorker2 int

	for k := 0; k < 4; k++ {
		numWorker2 = numWorkerInitial2 * int(math.Pow(2.0, float64(k)))
		fmt.Printf("-- Test Matrix Vector Multiplication (%d threads)\n", numWorker2)

		maxErrPercent := 0.0
		minErrPercent := 100.0
		maxErrAmount := 0.0
		minErrAmount := 100.0
		totalElapsed := 0.0
		totalTreewise := 0.0

		for iter := 0; iter < iterationCount2; iter++ {
			start := time.Now()

			if doParallel2 {
				// === Parallel section ===
				var wg sync.WaitGroup
				for w := 0; w < numWorker2; w++ {
					wg.Add(1)
					go func(wid int) {
						defer wg.Done()

						encoderSh := encoder.ShallowCopy()
						encSh := enc.ShallowCopy()
						decSh := dec.ShallowCopy()
						evalSh := eval.ShallowCopy()

						for i := wid; i < rows; i += numWorker2 {
							MatrixVectorMul_(params, *encSh, *decSh, *evalSh, *encoderSh,
								results, mat[i], vec,
								i, slots, wid, tolerance)
						}
					}(w)
				}
				wg.Wait()

				treeStart := time.Now()
				mulRes, err := TreewiseSum(eval, results)
				if err != nil {
					panic(err)
				}
				treeEnd := time.Since(treeStart).Seconds()
				totalTreewise += treeEnd

				// Decode & Decrypt
				vec_res := make([]float64, rows)
				pt_res := ckks.NewPlaintext(params, mulRes.Level())
				dec.Decrypt(mulRes, pt_res)
				if err := encoder.Decode(pt_res, vec_res); err != nil {
					panic(err)
				}

				elapsed := time.Since(start).Seconds()
				totalElapsed += elapsed

				// Error computation
				for i := 0; i < rows; i++ {
					expVal := 0.0
					for j := 0; j < cols; j++ {
						expVal += mat[i][j] * vec[j]
					}

					errAmount := math.Abs(expVal - vec_res[i])
					errPercent := (errAmount / math.Abs(expVal)) * 100

					if errPercent > maxErrPercent {
						maxErrPercent = errPercent
						maxErrAmount = errAmount
					}
					if errPercent < minErrPercent {
						minErrPercent = errPercent
						minErrAmount = errAmount
					}
				}

			} else {
				start := time.Now()
				vec_res := matrixVectorMul(rows, slots, params, *enc, *dec,
					*eval, *encoder, -1)
				elapsed := time.Since(start).Seconds()
				totalElapsed += elapsed

				// Error computation
				for i := 0; i < rows; i++ {
					expVal := 0.0
					for j := 0; j < cols; j++ {
						expVal += mat[i][j] * vec[j]
					}

					errAmount := math.Abs(expVal - vec_res[i])
					errPercent := (errAmount / math.Abs(expVal)) * 100

					if errPercent > maxErrPercent {
						maxErrPercent = errPercent
						maxErrAmount = errAmount
					}
					if errPercent < minErrPercent {
						minErrPercent = errPercent
						minErrAmount = errAmount
					}
				}
			}
		}

		fmt.Printf("\tAVERAGE TIME OVER ITERATIONS (%d threads): %.6f seconds per iteration\n", numWorker2, totalElapsed/float64(iterationCount2))
		fmt.Printf("MAXIMUM ERROR PERCENTAGE: %.6f with error amount: %.6e\n", maxErrPercent, maxErrAmount)
		fmt.Printf("MINIMUM ERROR PERCENTAGE: %.6f with error amount: %.6e\n", minErrPercent, minErrAmount)
		fmt.Printf("Elapsed Treewise (avg): %.6f seconds.\n\n", totalTreewise/float64(iterationCount2))
	}
}
