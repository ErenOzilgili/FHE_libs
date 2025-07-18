# FHE Libraries Comparison

## a) How to Setup

First of all, update the submodules (Initial use):
- git submodule update --init --recursive
For pulling the latest changes made to the submodules (For later use):
- git submodule update --remote --merge

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
Similar to SEAL, execute the following (from root folder):
(Note: Set -DWITH_OPENMP=OFF or ON depending on needing it below)

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
- SEAL_lib/multithread_seal_inner.cpp
- OpenFHE_lib/multithread_openfhe_inner.cpp
- Lattigo_lib/multithread_lattigo_inner.go

Executables (SEAL and OpenFHE) can be found at:
- build/SEAL_lib/multithread_seal_inner
- build/OpenFHE_lib/multithread_openfhe_inner

Execute the Lattigo code:
- go run multithread_lattigo_inner.go


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

    All threads finished.
    With 4 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time: 0.740448

    All threads finished.
    With 4 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time: 1.49921

    All threads finished.
    With 4 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time: 2.99344

    All threads finished.
    With 4 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time: 5.94992

    All threads finished.
    With 4 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time: 11.8327

    All threads finished.
    With 4 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time: 23.9272

    All threads finished.
    With 4 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time: 47.3824

    All threads finished.
    With 4 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time: 95.02

    All threads finished.
    With 4 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time: 191.829

    All threads finished.
    With 4 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time: 384.866

    ------------------------------------------
    ------------------------------------------

    All threads finished.
    With 8 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time: 0.830559

    All threads finished.
    With 8 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time: 1.19929

    All threads finished.
    With 8 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time: 2.29384

    All threads finished.
    With 8 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time: 5.02956

    All threads finished.
    With 8 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time: 10.3337

    All threads finished.
    With 8 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time: 20.2506

    All threads finished.
    With 8 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time: 39.768

    All threads finished.
    With 8 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time: 80.0157

    All threads finished.
    With 8 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time: 159.542

    All threads finished.
    With 8 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time: 319.289

    ------------------------------------------
    ------------------------------------------

------(With OMP - Multithreaded)

    All threads finished.
    With 4 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time: 0.866631

    All threads finished.
    With 4 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time: 1.78143

    All threads finished.
    With 4 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time: 3.65628

    All threads finished.
    With 4 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time: 7.57688

    All threads finished.
    With 4 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time: 14.3016

    All threads finished.
    With 4 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time: 28.0572

    All threads finished.
    With 4 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time: 54.9689

    All threads finished.
    With 4 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time: 110.019

    All threads finished.
    With 4 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time: 220.283

    All threads finished.
    With 4 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time: 440.402

    ------------------------------------------
    ------------------------------------------

    All threads finished.
    With 8 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time: 0.99255

    All threads finished.
    With 8 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time: 1.27781

    All threads finished.
    With 8 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time: 2.64398

    All threads finished.
    With 8 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time: 5.64134

    All threads finished.
    With 8 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time: 11.1204

    All threads finished.
    With 8 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time: 22.7396

    All threads finished.
    With 8 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time: 43.7727

    All threads finished.
    With 8 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time: 89.2794

    All threads finished.
    With 8 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time: 176.927

    All threads finished.
    With 8 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time: 350.999

    ------------------------------------------
    ------------------------------------------
    

------(With OMP - No Multithreading)

    No threads.
    With 0 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time: 2.8562

    No threads.
    With 0 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time: 5.65866

    No threads.
    With 0 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time: 11.3246

    No threads.
    With 0 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time: 27.0011

    No threads.
    With 0 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time: 49.7158

    No threads.
    With 0 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time: 89.5842

    No threads.
    With 0 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time: 179.239

    No threads.
    With 0 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time: 358.384

    No threads.
    With 0 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time: 715.086

    ------------------------------------------
    ------------------------------------------

### c.3) Lattigo

----------------------
------(Multithreading)
----------------------

    All threads finished.
    With 4 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time : 0.115256

    All threads finished.
    With 4 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time : 0.241784

    All threads finished.
    With 4 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time : 0.440870

    All threads finished.
    With 4 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time : 0.859667

    All threads finished.
    With 4 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time : 1.615897

    All threads finished.
    With 4 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time : 3.198085

    All threads finished.
    With 4 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time : 6.393100

    All threads finished.
    With 4 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time : 12.806855

    All threads finished.
    With 4 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time : 26.574206

    All threads finished.
    With 4 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time : 53.064245

    --------------------------------
    --------------------------------

    All threads finished.
    With 8 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time : 0.145080

    All threads finished.
    With 8 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time : 0.228731

    All threads finished.
    With 8 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time : 0.396026

    All threads finished.
    With 8 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time : 0.857045

    All threads finished.
    With 8 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time : 1.676459

    All threads finished.
    With 8 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time : 3.243763

    All threads finished.
    With 8 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time : 6.470056

    All threads finished.
    With 8 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time : 12.768996

    All threads finished.
    With 8 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time : 25.496071

    All threads finished.
    With 8 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time : 50.831204

    --------------------------------
    --------------------------------

-------------------------
------(No Multithreading)
-------------------------

    No threads.
    With 0 threads -- On 4 ciphertexts, each inner producted with itself.
            Total time : 0.533405

    No threads.
    With 0 threads -- On 8 ciphertexts, each inner producted with itself.
            Total time : 0.912365

    No threads.
    With 0 threads -- On 16 ciphertexts, each inner producted with itself.
            Total time : 1.547280

    No threads.
    With 0 threads -- On 32 ciphertexts, each inner producted with itself.
            Total time : 3.408714

    No threads.
    With 0 threads -- On 64 ciphertexts, each inner producted with itself.
            Total time : 6.691550

    No threads.
    With 0 threads -- On 128 ciphertexts, each inner producted with itself.
            Total time : 13.695425

    No threads.
    With 0 threads -- On 256 ciphertexts, each inner producted with itself.
            Total time : 29.008357

    No threads.
    With 0 threads -- On 512 ciphertexts, each inner producted with itself.
            Total time : 57.022668

    No threads.
    With 0 threads -- On 1024 ciphertexts, each inner producted with itself.
            Total time : 108.860094

    No threads.
    With 0 threads -- On 2048 ciphertexts, each inner producted with itself.
            Total time : 217.541631

    --------------------------------
    --------------------------------





  
  



