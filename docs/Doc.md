# Documentation on Pyfhel


## 1. Cloning & Installation
Follow the instructions in the document 'INSTALL.md'. 

- *EASY INSTALL* can be used (only 2 shell commands!) but it is not recommended unless your OS is Ubuntu (Due to package manager 'apt', location of shared files, etc...)
- *NORMAL INSTALLATION* is the preferred procedure, explained step-by-step in the INSTALL.md document.

The installation relies heavily on **Makefiles** (src/.Makefiles folder, moved to their respective folders by src/configure). In case there is anything wrong with your *NORMAL INSTALLATION*, you can check them and maybe adjust some variables. All of the Makefiles have been heavily commented and cleaned. In order to know what commands are available, just run `make info`. In general, Makefiles include an uninstall command (`make uninstall`) to undo the installation, and a clean command (`make clean`) to erase all non-source files.

### Dependencies
The dependencies between the different libraries included in this project are:
   **Pyfhel -> Afhel -> HElib**

Additionally, there are some Packages and Libraries required for the installation & compilation of all three:

| Requirements             | Names                           | Installation process                   |
|--------------------------|---------------------------------|----------------------------------------|
| Required Packages        | Boost, Python-dev, pip, libtool, m4 | sudo apt-get                           |
| Required Lib Downloads   | NTL, GMP                        | Download .tar.bz2, make, sudo make install |
| Required Python Packages | Cython, numpy                   | sudo pip install                       |

*NOTE: the package manager in this installation was *apt* (Ubuntu). In case you're running a different Linux distribution, use your own package manager (e.g.: rpm,...). If you are running Ubuntu, you may want to perform the EASY INSTALL*

    
#### What the Installation does
First of all, all the requirements for *HElib* & *Afhel* & *Pyfhel* are installed (details about them in INSTALL.md). Next, it installs *HElib* and *Afhel* as **shared libraries** (named _fhe_ and _afhel_ respectively) using `libtool` {} (yes! even though the original *HElib* was a static library, this project has modified the installation for it to be available all across the system), and copies the header files to a well-known folder {/usr/local/include by default}. Lastly, *Pyfhel* is installed as a **Python module** using `pip`.

---------------

## 2. Usage

The **basic** use of each library (*HElib*, *Afhel* & *Pyfhel*) is shown in their respective demos in the folder _src/Demos\_Tests_. These constitute the basic usage of both (more advanced uses of HElib are found in their repository). Nonetheless, we include here some hints:

### 2.1. Pyfhel (Python2.7)
1. Import the three main classes:

       > from Pyfhel import Pyfhel        -> Core class
      
       > from PyPtxt import PyPtxt        -> Plaintext Python class 
       
       > from PyCtxt import PyCtxt        -> Cyphertext Python class

2. Setup Context: Define a Pyfhel object and perform keyGen/import saved context&keys (more about this bellow)

3. Create a plaintext (PyPtxt) and encrypt it into a cyphertext (PyCtxt). Plaintexts can be created from either a list of numbers ([1,2,3,4]) or a list of lists of numbers ([[1,2,3,5], [12,133],[4]]).

4. Perform Operations, such as:
- *sum*: ctxt1 + ctxt2 (or ctxt1 += ctxt2)
- *mult*: ctxt1 * ctxt2 (or ctxt1 \*= ctxt2)
- *scalarProd*: ctxt1 @ ctxt2 (or ctxt1 @= ctxt2)
- *square*: ctxt1 = ctxt1 ** 2 (or ctxt1 \*\*= 2)
- *cube*: ctxt1 = ctxt1 ** 3 (or ctxt1 \*\*= 3)

5. Decrypt the result, obtaining always a list of lists of integers.

If you want to see an example of this, run `python Demo_Pyfhel.py` in the src/Demos_Tests directory. This demo shows an example of a very simple sumation and multiplication of two cyphertexts, with verbose comments. You can also run `python` to open an ineractive console and then run inside it `execfile('Demo_Pyfhel.py')`. This way you will also be able to play with the results. 

### 2.2. Afhel & HElib (C++)
Include the headers in the top of your source file:

      #include "FHE.h"             // HElib 
      #include "Afhel.h"           // Afhel
      
Using the libraries is fairly similar to the processyin Pyfhel, but with a different syntax. Refer to the Demos for details.      
      
Compile your program named '_mySourceFileName.cpp_' into an executable '_myExecutableName_' using the following flags: 

      > g++ -g -O2 -std=c++11 -pthread -DFHE_THREADS -DFHE_DCRT_THREADS -DFHE_BOOT_THREADS \
            -lm -lgmp -lntl -lfhe -lafhel -o myExecutableName mySourceFileName.cpp

To make your life easier, you can also do an EASY COMPILATION of '_mySourceFileName.cpp_' by running inside the src/, src/Afhel or src/Demos_Tests this command:
      
      > make '_mySourceFileName\_x_'

If you want see an example of Afhel, compile the Demo, run `make Demo_Afhel_x` in the src/Demos_Tests and you should be getting an executable with that name in the same directory. This demo shows an example of a very simple sumation and multiplication of two cyphertexts, with verbose comments. Run it by executing `./Demo_Afhel_x`.

----------------------------------

## 3. Tests & Demos

The demos have been exhaustively commented in order to provide as much clear information as possible. In comparison, the tests are more focused in benchmarking different possibilities for implementing algorithms.
- Demo_Afhel.cpp - Basic usage of Afhel library
- Demo_HElib.cpp - Basic usage of HElib
- Demo\_Pyfhel.py - Basic usage of Pyfhel: Run tests on the basic operations of Pyfhel. To know which parameters you can provide to the program, you can use: python Demo\_Pyfhel -h 
- Demo\_Pyfhel\_binary.py - Using Pyfhel for binary operations. Acknowledgemetns to [Tarek Aoukar @severos](https://github.com/severos)
- Demo\_AfhelRestored.cpp - Using Afhel after restoring the environment (requires previous run of Demo\_Afhel)
- Demo\_HElib\_SimpleIO.cpp - Saving & Restoring context data
- Test\_sum\_HElib.cpp - Three methods to perform addition. Acknowledgements to [Matheus S. H. Cruz](https://github.com/mshcruz/SumEncryptedVectors)
- Test\_scProd\_HElib.cpp - Three methods to perform scalar product. Acknowledgements to [Matheus S. H. Cruz](https://github.com/mshcruz/ScalarProductFHE) 
- Demo\_Pyfhel\_ScalProd.py - Use of scalar product in Pyfhel.

-------------------------------------

## 4. TIPS & TRICKS based on experience

* First of all: Remember that this library is **not using float arithmetic**! if you want to use floats, you should consider checking on [SEAL]( http://sealcrypto.org/). Nevertheless, using a high enough cyphertext space can prove to be sufficient.
* **KeyGen** (a.k.a. key generation and context creation) takes a somewhat long time, and the choice of parameters is determinant for the general performance of the library:

| Parameter  | Description                                        | Default/Recommended Value(s)                                                                                                                                                                                                                                                                         |
|------------|----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| p          | Plaintext base. All operations are modulo p^r.     | 2. It has to be prime. For a faster execution, try a tradeoff p - r so that a value close to 2^40 is achieved (e.g.: 253^5)                                                                                                                                 |
| r          | Plaintext exponent. All operations are modulo p^r. | 40, for p=2. Other values of r can be used depending on the value of p.                                                                                                                                                                                                                                                        |
| c          | # Columns in key switching matrix                  | Affects performance, since it provides a higher security at a higher cost. Set to 1 if not testing security. Set to 3 for secure version.                                                                                                                                                            |
| d          | Degree of field extension                          | Somewhat obscure. Default to 0.                                                                                                                                                                                                                                                                      |
| sec        | Number of bits in public/private keys              | Affects performance greatly. Higher security at considerable cost. Set to 30 if not testing security. Set to >128 for secure version.                                                                                                                                                                |
| W          | Hamming weight of  secret key                      | Cannot be higher than sec. 0 means absolutely insecure. Recommended: sec/2                                                                                                                                                                                                                           |
| L          | # Levels in modulus chain                          | It defines the maximum number of operations that can be performed without corrupting data. If unset, a heuristic                                                                                                                                                                                     |
| m          | Use m'th cyclotomic polynomial as specific modulus | Completely obscure. Luckily, Afhel & Pyfhel can compute a heuristic. Leave it to them (blank)                                                                                                                                                                                                        |
| R          | Number of expected rounds of multiplication        | Used to generate a L if the heuristic version of L is used. It's an approximate                                                                                                                                                                                                                      |
| s          | Minimum number of slots for the vectors            | Vectors can apply operations to all their values in one single instruction. The more values, the better, but it slows down KeyGen. Vector size is determined by variable nSlots (or numSlots), arround 100-500 depending on other parameters. Leave to 0 or empty by default, but could be changed.  |
| gens, ords | Vectors of generators and orders                   | Obscure. Leave empty, the libraries won't complain.                                                                                                                                                                                                                                                  |

* Using the right value for the parameters **p** and **r** is crucial, since all the operations are performed modulo **p^r**! It must be prime. If you use a small value you get much faster KeyGen, but at the cost of requiring some conversion of the results to more suitable data types. Very high values of `p` didn't seem to work correctly in the past, but recently HElib has been fixed and they seem to work. The values that have been tried so far (even though no extensive tests have been done for any of them):
          
          * 2 (Equivalent to binary)
          * 257 (Equivalent to Byte)
          * 65537 (Equivalent to Word)
          * 4294967311 (Equivalent to Long)

----------------------------------
