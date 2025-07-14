# FHE Libraries Comparison

## a) How to Setup

First of all, update the submodules (Initial use):
    git submodule update --init --recursive
For pulling the latest changes made to the submodules (For later use):
    git submodule update --remote --merge

### a.1) Building Microsoft SEAL
For building SEAL, follow the below commands (from root folder):

    mkdir build-seal && cd build-seal

    cmake ../external/SEAL \
    -DCMAKE_INSTALL_PREFIX=../install-seal \
    -DSEAL_USE_ZSTD=OFF \
    -DSEAL_USE_ZLIB=OFF

    cmake --build .
    cmake --install .

### a.2) Building OpenFHE
Similar to SEAL, we do (from root folder):

    mkdir build-openfhe && cd build-openfhe

    cmake ../external/openfhe-development \
    -DCMAKE_INSTALL_PREFIX=../install-openfhe \
    -DWITH_OPENMP=OFF \
    -DCMAKE_BUILD_TYPE=Release

    cmake --build .
    cmake --install .

### a.3) Generating Executables and Running (SEAL, OpenFHE, Lattigo)
After the above succesfully prepares the OpenFHE and/or SEAL object files, run (from root folder):

    mkdir build && cd build
    cmake ..
    cmake --build .

Source code for files to be executed are at:
- SEAL_lib/
- OpenFHE_lib/multithread_openfhe_inner.cpp
- Lattigo_lib/multithread_lattigo_inner.go

Executables (SEAL and OpenFHE) can be found at:
- build/SEAL_lib/multithread_seal_inner
- build/OpenFHE_lib/multithread_openfhe_inner

Execute the Lattigo code:
    go run multithread_lattigo_inner.go


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

I have 4 physical and 8 virtual cores, so the thread amounts tried are 4 and 8.

CPU Information
---------------
Model: Intel(R) Core(TM) i5-9300H CPU @ 2.40GHz
Base Clock Speed: 2.40 GHz
Physical Cores: 4
Logical Processors (Threads): 8
Sockets: 1
Virtualization: Enabled
Cache:
  L1 Cache: 256 KB
  L2 Cache: 1.0 MB
  L3 Cache: 8.0 MB

CKKS Vectors
------------
Polynomial degree was set to 8192 with 4096 slots filled randomly with numbers between (-5.0, 5.0).
The below times also include the encryption times.

### c.1) Microsoft SEAL
----------------------
------(Multithreading)
----------------------

    All threads finished.
    With 4 threads -- On 4 ciphertexts, each inner producted with itself.
    	Total time: 0.102512
    
    All threads finished.
    With 4 threads -- On 8 ciphertexts, each inner producted with itself.
    	Total time: 0.214751
    
    All threads finished.
    With 4 threads -- On 16 ciphertexts, each inner producted with itself.
    	Total time: 0.422005
    
    All threads finished.
    With 4 threads -- On 32 ciphertexts, each inner producted with itself.
    	Total time: 0.83706
    
    All threads finished.
    With 4 threads -- On 64 ciphertexts, each inner producted with itself.
    	Total time: 1.66186
    
    All threads finished.
    With 4 threads -- On 128 ciphertexts, each inner producted with itself.
    	Total time: 3.32624
    
    All threads finished.
    With 4 threads -- On 256 ciphertexts, each inner producted with itself.
    	Total time: 6.68255
    
    All threads finished.
    With 4 threads -- On 512 ciphertexts, each inner producted with itself.
    	Total time: 13.2479
    
    All threads finished.
    With 4 threads -- On 1024 ciphertexts, each inner producted with itself.
    	Total time: 26.3365
    
    All threads finished.
    With 4 threads -- On 2048 ciphertexts, each inner producted with itself.
    	Total time: 52.9306
    
    ------------------------------------------
    ------------------------------------------
    
    All threads finished.
    With 8 threads -- On 4 ciphertexts, each inner producted with itself.
    	Total time: 0.114328
    
    All threads finished.
    With 8 threads -- On 8 ciphertexts, each inner producted with itself.
    	Total time: 0.209074
    
    All threads finished.
    With 8 threads -- On 16 ciphertexts, each inner producted with itself.
    	Total time: 0.419095
    
    All threads finished.
    With 8 threads -- On 32 ciphertexts, each inner producted with itself.
    	Total time: 0.826162
    
    All threads finished.
    With 8 threads -- On 64 ciphertexts, each inner producted with itself.
    	Total time: 1.74596
    
    All threads finished.
    With 8 threads -- On 128 ciphertexts, each inner producted with itself.
    	Total time: 3.42285
    
    All threads finished.
    With 8 threads -- On 256 ciphertexts, each inner producted with itself.
    	Total time: 6.62158
    
    All threads finished.
    With 8 threads -- On 512 ciphertexts, each inner producted with itself.
    	Total time: 13.1055
    
    All threads finished.
    With 8 threads -- On 1024 ciphertexts, each inner producted with itself.
    	Total time: 26.0905
    
    All threads finished.
    With 8 threads -- On 2048 ciphertexts, each inner producted with itself.
    	Total time: 52.3088
    
    ------------------------------------------
    ------------------------------------------

-------------------------
------(No Multithreading)
-------------------------

    No threads.
    With 0 threads -- On 4 ciphertexts, each inner producted with itself.
    	Total time: 0.308585
    
    No threads.
    With 0 threads -- On 8 ciphertexts, each inner producted with itself.
    	Total time: 0.614652
    
    No threads.
    With 0 threads -- On 16 ciphertexts, each inner producted with itself.
    	Total time: 1.22699
    
    No threads.
    With 0 threads -- On 32 ciphertexts, each inner producted with itself.
    	Total time: 2.46338
    
    No threads.
    With 0 threads -- On 64 ciphertexts, each inner producted with itself.
    	Total time: 4.92607
    
    No threads.
    With 0 threads -- On 128 ciphertexts, each inner producted with itself.
    	Total time: 9.84045
    
    No threads.
    With 0 threads -- On 256 ciphertexts, each inner producted with itself.
    	Total time: 19.8526
    
    No threads.
    With 0 threads -- On 512 ciphertexts, each inner producted with itself.
    	Total time: 39.5042
    
    No threads.
    With 0 threads -- On 1024 ciphertexts, each inner producted with itself.
    	Total time: 78.6996
    
    No threads.
    With 0 threads -- On 2048 ciphertexts, each inner producted with itself.
    	Total time: 167.09
    
    ------------------------------------------
    ------------------------------------------

### c.2) OpenFHE

------(With OMP disabled - Multithreaded)

------(With OMP - Multithreaded)

    All threads finished.
    With 4 threads -- On 4 ciphertexts, each inner producted with itself.
    	Total time: 1.08249
    
    All threads finished.
    With 4 threads -- On 8 ciphertexts, each inner producted with itself.
    	Total time: 2.22044
    
    All threads finished.
    With 4 threads -- On 16 ciphertexts, each inner producted with itself.
    	Total time: 4.63852
    
    All threads finished.
    With 4 threads -- On 32 ciphertexts, each inner producted with itself.
    	Total time: 8.65749
    
    All threads finished.
    With 4 threads -- On 64 ciphertexts, each inner producted with itself.
    	Total time: 17.3919
    
    All threads finished.
    With 4 threads -- On 128 ciphertexts, each inner producted with itself.
    	Total time: 34.5726
    
    All threads finished.
    With 4 threads -- On 256 ciphertexts, each inner producted with itself.
    	Total time: 68.627
    
    All threads finished.
    With 4 threads -- On 512 ciphertexts, each inner producted with itself.
    	Total time: 137.238
    
    All threads finished.
    With 4 threads -- On 1024 ciphertexts, each inner producted with itself.
    	Total time: 273.473
    
    All threads finished.
    With 4 threads -- On 2048 ciphertexts, each inner producted with itself.
    	Total time: 548.757
    
    ------------------------------------------
    ------------------------------------------

------(With OMP - No Multithreading)

### c.3) Lattigo




  
  



