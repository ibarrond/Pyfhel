## Instalation of Afhel
1. **INSTALL HELIB DEPENDENCIES**
   
   In order to build HElib, you need to have GMP and NTL libraries installed.
   * GMP:  GNU Multiple Precision Arithmetic Library   
        * Download GMP from http://www.gmplib.org. On this case I chose the .bz2 file:

	     > `gmp-X.Y.Z.tar.bz2`

        * uncompress and cd into the directory:

	     > `bzip2 -d gmp-X.Y.Z.tar.bz2`
         > `tar xvf gmp-X.Y.Z.tar`
         > `cd gmp-X.Y.Z`

        * Install it by running on the command line in this order:
         
         > `./configure` -> If you get error '...: No usable m4 in $PATH ...', install m4 by running `sudo apt-get install m4`
         > `make`
         > `sudo make install`

   * NTL: Number Theory Library

        * Download NTL from http://www.shoup.net/ntl/download.html. I chose the .tar.gz:

         > `ntl-X.Y.Z.tar.gz`

        * uncompress and cd into the directory ntl-XXX/src

         > `tar xvf ntl-X.Y.Z.tar.gz`
         > `cd ntl-X.Y.Z/src`

        * On the command line run, in this order:

             > `./configure NTL_GMP_LIP=on SHARED=on`
             > `make`
             
             > sudo make install
        * We need to create a symbolic link for the shared library. Run:
             
             > /usr/local/lib/

          Here you should see an object like libntl.so.XX, where XX is a two digit number. Run, replacing the XX by the number:
            
             > sudo ln -s /usr/local/lib/libntl.so.XX /usr/lib/libntl.so.XX


2. **INSTALL HELIB**
    
   Download the repository
   
    > git clone https://github.com/shaih/HElib.git
  
   On the command line run these commands while inside the HElib/src directory:
     > make                `--> compile and build the library fhe.a.`
     > 
     > make check          `--> compile and runs Test_*.cpp programs.`

3. **INSTALL BOOST**
    
   Boost is a C++ library that will allow us to create map objects to store our Cyphertexts. Run:

     > sudo apt-get install libboost-all-dev

4. **INSTALL CYTHON**
    
    Cython allows us to bridge between the world of C++ and the world of Python. Run:

     > sudo pip install cython

    Found any issues? maybe you should check if you have previously installed pip and a developper version of python (vanilla Ubuntu and Fedora normally don't come with it):
     
     > sudo apt-get install python-dev
     > sudo apt-get install python-pip
     > sudo apt-get install python3-dev
     > sudo apt-get install python3-pip

5. **INSTALL AFHEL**

     Go inside the Afhel directory and run:

     > make clean               // This gets rid of any previous files

     > make

6. **INSTALL PYFHEL**

     Get inside the Pyfhel subdirectory and run:

     > sudo python setup.py install

     Just like we did for NTL, we want this library to be fully available, which is why we're turning it into a shared library. We just need to create a link in both python libraries:

     > sudo ln -s /usr/local/lib/libntl.so.10 /usr/lib/libntl.so.10

     


## Compile program
If you want to build your own program based on HElib (and Afhel), the easiest way to do it is to write the program in a file called program.cpp and run:
> make myprog_x    `--> removing the ".cpp" and adding "_x" to the name`

This will compile myprog.cpp and link in fhe.a, Afhel.a and all required support libraries, and create the executable program_x. You should only do this while inside the Afhel root folder; nevertheless, it also works inside HElib/src (the difference being that inside the HElib/src you won't have access to the Afhel class).

If you find any problems while compiling a program, try removing some parameters from the CFLAGS variable (3rd line) inside the Makefile. `-std=c++11` generates problems sometimes.

---------------

# Write my own program

## Writing a program for HElib
We are gonna use the Demo_HElib.cpp as example. The first step is to include the appropiate headers. After that, there are 5 different sections in the program:
1. SETUP CONTEXT: Create context variables, same notation as the one in the papers
2. KEY GENERATION
3. ENCRYPTION
4. OPERATION
5. DECRYPTION

If you want to run the program, it's better to first remove the previous `Demo_HElib_x` file. Then you should run `make Demo_HElib_x` and you should be getting an executable. This demo shows an example of a very simple sumation and multiplication of two cyphertexts, with verbose comments.

## Writing a program for Afhel
As his name suggests, Afhel implements a higher level of abstraction than the one from HElib, and handles Cyphertexts using an unordered map that is accessed via keys of type string.

The file Demo_Afhel.cpp shows the simple functioning of the program.

## Writing a program in Python using Pyfhel
Piece of cake. Check out the Demo, it is really self-explanatory. It doesn't get any better than this!

# Tests & Demos
The demos have been exhaustively commented in order to provide as much clear information as possible. In comparison, the tests are more focused in benchmarking different possibilities for implementing algorithms.
- Demo_AfHEl.cpp - Basic usage of Afhel library
- Demo_HElib.cpp - Basic usage of HElib
- Demo_Pyfhel.py - Basic usage of Pyfhel
- Test_sum_HElib.cpp - Three methods to perform addition.
- Test_scProd_HElib.cpp - Three methods to perform scalar product. 
In order to run any of the tests you should compile them first.

# TIPS & TRICKS based on experience
* Using the right value for the parameter `p` is crucial! It must be prime. If you use a small value you get much faster KeyGen, but at the cost of requiring some conversion of the results to more suitable data types. Very high values of `p` didn't seem to work correctly in the past, but recently HElib has been fixed and they seem to work. The values that have been tried so far (even though no extensive tests have been done for any of them):
    * 2 (Equivalent to binary)
    * 257 (Equivalent to Byte)
    * 65537 (Equivalent to Word) [The one we consider best choice]
    * 4294967311 (Equivalent to Long) -> It took a considerable amount of time (15 mins?) to setup its context, but on the other hand you can work without implementing any conversion.
* The slowest section of the whole process is, by far, the "Setup context". Declaration of the context the first time and reusage of the same context in exhaustive tests is a must! That's why it's strongly encouraged to use Pyfhel in an interactive Python environment: once defined, you can reuse that context for the rest of your tests! In comparison, running independent tests in C++ are heavily penalized by this (specially when you use higher values of the modulus p).
* The library is supposed to automatically tell you if the noise level is too high to recover the right value, but it doesn't work in general, and this is neither covered by Afhel nor Pyfhel.
