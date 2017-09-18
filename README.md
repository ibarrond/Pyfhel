# Afhel & Pyfhel

## Afhel: Abstraction For HELib 
Afhel is a library that creates an abstraction over the basic functionalities of HElib as a Homomorphic Encryption library, such as addition, multiplication, scalar product and such. The repository includes demos for helib, tests for different ways to implement helib's funcitonalities and a demo for Afhel.

## Pyfhel: PYthon For HELib
Built on top of Afhel, Pyfhel is a python module that takes simplicity iven further when playing with HElib, allowing the use of HElib inside Python and with a syntax similar to normal arithmetics. We can use this with any implementation done in Python, be it normal encryption or maybe some Machine Learning algorithm!. In order to get to know how it works, check the Demo_Pyfhel.py

------------

## 1. Instalation
Follow the instructions in the document 'INSTALL.md':

- Installation of Afhel is up to section 4.
- Installation of Pyfhel on top of Afhel involves sections 5 and 6.
     


---------------

## 2. Usage of Afhel

### 2.1. Write your program program

#### 2.1.1. Write a basic program for HElib

You should use the Demo_HElib.cpp as template. The first step is to include the appropiate headers:

> #include "FHE.h"

After that, there are 5 different sections in the program:

1. SETUP CONTEXT: Create context variables
2. KEY GENERATION: Creates the Private/Public Key pair
3. ENCRYPTION: Create the Plaintexts and encrypts them into Cyphertexts
4. OPERATION: Perform sums, multiplications and so on over the encrypted Cyphertexts.
5. DECRYPTION: Decrypt the resulting Cyphertexts

If you want to compile the demo, run `make Demo_HElib_x` and you should be getting an executable with that name in the same directory. This demo shows an example of a very simple sumation and multiplication of two cyphertexts, with verbose comments.

#### 2.1.2. Write a basic program for Afhel

The file Demo_Afhel.cpp shows the simple functioning of the program, while the complete API is described in Afhel.h.

First of all you need to include the library in the header:

> #include "Afhel.h"

Then you create an Afhel object (called `he` in the demo) that you will use to call all the functions, and you follow the same order as with HElib, this time using the `keyGen`, `encrypt`, `decrypt`, `add`, `mult`, `scalarProd` or `square` functions that are defined inside Afhel.h (e.g.: `he.add(k1, k2)`).

### 2.2. Compile your program

If you want to build your own program based on Afhel (and HElib), the easiest way to do it is to write the program in a file called program.cpp inside the root directory and run:
> make myprog_x    `--> removing the ".cpp" and adding "_x" to the name`

This will compile myprog.cpp and link in fhe.a, Afhel.a and all required support libraries, and create the executable program_x. You should only do this while inside the Afhel root folder; nevertheless, it also works inside HElib/src (the difference being that inside the HElib/src you won't have access to the Afhel class).

If you find any problems while compiling a program, try removing some parameters from the CFLAGS  (3rd line inside the Makefile). `-std=c++11` generates problems sometimes.

### 2.3. Details of Afhel
Afhel implements a higher level of abstraction than the one from HElib, and handles Cyphertexts using an unordered map (key-value pairs) that is accessed via keys of type string. This is done in order to manage Cyphertext using references (the keys), which will allow Pyfhel to work only using strings (keeping the Cyphertexts in C++). Afhel also compresses the Context setup and Key generation into one single KeyGen function with multiple parameter selection.


## 3. Usage of Pyfhel

Check out the Demo_Afhel.py, it is really self-explanatory. It doesn't get any better than this! First you import all the modules:

> from Pyfhel import Pyfhel        -> Core class
> from PyPtxt import PyPtxt        -> Plaintext Python class 
> from PyCtxt import PyCtxt        -> Cyphertext Python class

Then you go over the same process as in Afhel (define Pyfhel object, keyGen, encrypt, operations, decrypt), with one peculiarity: the operations can be performed directly over the Cyphertexts using standard arithmetic notation:

- sum: ctxt1 + ctxt2 (or ctxt1 += ctxt2)
- mult: ctxt1 * ctxt2 (or ctxt1 \*= ctxt2)
- scalarProd: ctxt1 @ ctxt2 (or ctxt1 @= ctxt2)

Inputs for the plaintexts and the output of the decryptions are lists of integers.


## 4. Tests & Demos

The demos have been exhaustively commented in order to provide as much clear information as possible. In comparison, the tests are more focused in benchmarking different possibilities for implementing algorithms.
- Demo_AfHEl.cpp - Basic usage of Afhel library
- Demo_HElib.cpp - Basic usage of HElib
- Demo_Pyfhel.py - Basic usage of Pyfhel
- Test_sum_HElib.cpp - Three methods to perform addition.
- Test_scProd_HElib.cpp - Three methods to perform scalar product. 
In order to run any of the tests you should compile them first.


## 5. TIPS & TRICKS based on experience

* First of all: Remember that this library is not using float arithmetic! if you want to use floats, you should consider checking on [SEAL](https://sealcrypto.codeplex.com/).
* Using the right value for the parameter `p` (in keyGen) is crucial! It must be prime. If you use a small value you get much faster KeyGen, but at the cost of requiring some conversion of the results to more suitable data types. Very high values of `p` didn't seem to work correctly in the past, but recently HElib has been fixed and they seem to work. The values that have been tried so far (even though no extensive tests have been done for any of them):
    * 2 (Equivalent to binary)
    * 257 (Equivalent to Byte)
    * 65537 (Equivalent to Word) [The one we consider best choice]
    * 4294967311 (Equivalent to Long) -> It took a considerable amount of time (15 mins?) to setup its context, but on the other hand you can work without implementing any conversion.
* The other parameters in keyGen (and setup context if using the originall HElib) can be played with. For didactic purposes, those parameters are:


* The slowest sections of the whole process are, by far, the "Setup context" and "KeyGen". Declaration of the context the first time and reusage of the same context is a must! That's why it's strongly encouraged to use Pyfhel in an interactive Python environment: once defined, you can reuse that context for the rest of your tests! In comparison, running independent tests in C++/Python are heavily penalized by this (specially when you use higher values of the modulus p).
* The library is supposed to automatically tell you if the noise level is too high to recover the right value and apply bootstrapping, but this is covered neitherby Afhel nor by Pyfhel.

# Author & Acknowledgements

- Author: Alberto Ibarrondo @ibarrond
- Tutor: Melek Onen
- Date: 13/06/2017

This library has been created for the project "Privacy for Big Data Analytics" in EURECOMThis SW is based on [HElib](https://github.com/shaih/HElib) by Shai Halevi, [HEIDE](https://github.com/heide-support/HEIDE) by Grant Frame, [analysis of addition](https://mshcruz.wordpress.com/2017/05/13/sum-of-encrypted-vectors/) by Matheus S.H. Cruz. In compliance with their respective Licenses, I keep a copy of the original licenses in the "Acknowledgements" folder, as well as reference to the changes commited to their originals. Also, the same type of license (GNU GLPv3) applies to Afhel & Pyfhel, as mandated. 
