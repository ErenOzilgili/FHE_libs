package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func innerProduct(params ckks.Parameters, enc rlwe.Encryptor, dec rlwe.Decryptor, eval ckks.Evaluator, encoder ckks.Encoder,
	slots int, tid int, tolerance float64) {
	// Generate random vector
	vec := make([]float64, slots)
	var expected float64
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(tid)))
	for i := range vec {
		val := 10 * (r.Float64() - 0.5)
		vec[i] = val
		expected += val * val
	}

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
	pt_res := ckks.NewPlaintext(params, result.Level())
	dec.Decrypt(result, pt_res)
	if err := encoder.Decode(pt_res, vec); err != nil {
		panic(err)
	}

	res := vec[0]
	if math.Abs(res-expected) > tolerance {
		log.Fatalf("TID %d: mismatch! expected %.4f, got %.4f", tid, expected, res)
	}
}

func main() {
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

	for k := 0; k < 2; k++ {
		//Do with 4 and 8 cores
		numWorker = numWorkerInitial * int(math.Pow(2.0, float64(k)))

		for j := 0; j < 10; j++ {
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
