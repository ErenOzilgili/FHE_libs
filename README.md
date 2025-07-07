# FHE Libraries Comparison

## a) How to Setup

## b) Libraries

### b.1) Microsoft SEAL
- No Internal Multithreading
  Microsoft SEAL does not spawn multiple threads internally for
  homomorphic operations. As of the latest versions, SEAL remains essentially single-threaded in its
  library code. All the parallelism must come from the application level.

- Thread-Safety
  Most of SEAL's classes are designed to be thread-safe. Most of the objects such as
  Encryptor, Decryptor, Evaluator are thread safe. Encryption parameters,
  keys, and ciphertext objects between threads can be shared for read or independent use.
  The SEAL library was updated in version 2.3.0 to better support multi-threaded applications.
  The keys and SEALContext itself are read-only during encryption/evaluation, so they remain
  “key-safe” for multithreading without needing per thread copies.

### b.2) OpenFHE
- Internal Multithreading
  OpenFHE  provides built-in multithreading for expensive homomorphic operations using OpenMP.
  Many low-level routines  are parallelized with (#pragma omp) directives in the code.

- Thread-Safety
  OpenFHE is not guaranteed to be thread-safe for arbitrary concurrent use
  (https://openfhe.discourse.group/t/makepackedplaintext-hangs-in-loop-parallelized-with-omp/2075).
  OpenFHE objects – such as the CryptoContext, PublicKey/SecretKey, and any Encryptor/Decryptor/Evaluator objects
  are not inherently thread-safe. These objects do not have built-in locks to prevent concurrent
  modifications, and certain internal routines perform one-time initializations or use shared resources
  that can cause race conditions if accessed from multiple threads simultaneously.
  
  "OMP (OpenMP) does not always work well with pthreads. I suggest turning off OMP by compiling it with the CMAKE flag WITH_OPENMP=OFF.
  Also, when using multithreading, make sure the code is written in a way where there are no shared variables/objects being
  updated at the same time."
  --> (https://openfhe.discourse.group/t/multi-threading-ciphertext-multiplication-and-bootstrapping/634)

  OpenFHE may perform lazy initialization of certain precomputed tables or caches (for example, NTT precomputation
  tables, random generator seeding, or key-switching hints) the first time an operation is invoked. If two
  threads attempt to perform such an initialization simultaneously, it can lead to crashes or deadlocks.

### b.3) Lattigo
- Internal Multithreading
  There is no built-in OpenMP-style multi-threading in the library code. Any multi-core parallelism
  should be done by the user.

- Thread-Safety
  Lattigo's API is not concurrency-safe if the same object is used in multiple goroutines.
  Encryptor, Decryptor, Evaluator instances across threads at the same time cannot be
  safely shared.
  --> (https://github.com/tuneinsight/lattigo/issues/422)

  However, objects can be shallow copied by using the ShallowCopy() method which creates a new
  instance and shares all read-only data with the original, but has its own working buffers.
  Any internal mutable state like PRNG (Pseudo random number generator) is reallocated for the new copy.
  --> (https://github.com/tuneinsight/lattigo/discussions/433)

  The cleanest way is to inside different go routines, giving each routine its own copy of the needed objects.

## c) Runtimes For Inner Products (CKKS)

### c.1) Microsoft SEAL
------(Multithreading)

------(No Multithreading)

### c.2) OpenFHE

------(With OMP disabled - Multithreaded)

------(With OMP - Multithreaded)

------(With OMP - No Multithreading)

### c.3) Lattigo




  
  



