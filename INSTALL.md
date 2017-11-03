# INSTALLATION OF PYFHEL

### Dependencies
The dependencies between the different libraries included in this project are:
   **Pyfhel -> Afhel -> HElib**

Additionally, there are some Packages and Libraries required for the installation & compilation of all three:

| Requirements             | Names                           | Installation process                   |
|--------------------------|---------------------------------|----------------------------------------|
| Required Packages        | Boost, Python-dev, PIP, libtool, m4 | sudo apt-get                           |
| Required Lib Downloads   | NTL, GMP                        | Download .tar.bz2, make, sudo make install |
| Required Python Packages | Cython                          | sudo pip install                       |

*NOTE: the package manager in this installation was *apt* (Ubuntu). In case you're running a different Linux distribution, use your own package manager (e.g.: rpm,...). If you are running Ubuntu, you may want to perform the EASY INSTALL*


------------------------------------

## EASY INSTALL
This method is not entirely supported, but it is the fastest. Don't use it unless your OS is Ubuntu. Run inside the src/ folder:
       
       > ./configure
       > sudo make all
       
It should take a long time (5-10 min), but if there is no error, everything should be installed. The easy install is equivalent to all the steps bellow (but it doesn't perform cleaning). If you get any errors, it is better to walk the long way and follow the full installation guide.

---------------------------------------

## INSTALL ALL REQUIREMENTS

1. **Required Packages**

   * **Python-dev**:  Developer version of Python 2.7 (no Python3 yet)
        
         > sudo apt-get install python-dev
         
   * **Boost**:  C++ library that will allow us to store our Cyphertexts in a map structure.
        
         > sudo apt-get install libboost-all-dev

   * **PIP**:  Package manager for Python, we'll use it to properly install Pyfhel
        
         > sudo apt-get install python-pip
         
   * **Libtool**:  Library manager for Linux. We'll use it to install HElib & Afhel
        
         > sudo apt-get install libtool-bin
         
   * **m4**:  Language to properly setup an installation for GMP
        
         > sudo apt-get install m4
   * **g++**: C++ compiler
   
         > sudo apt-get install build-essential g++
         
2. **Required Lib Downloads**

   * GMP:  GNU Multiple Precision Arithmetic Library
        * Download GMP from http://www.gmplib.org. On this case I chose the .bz2 file:

         > gmp-X.Y.Z.tar.bz2

        * uncompress and cd into the directory:

         > bzip2 -d gmp-X.Y.Z.tar.bz2
         > tar xvf gmp-X.Y.Z.tar
         > cd gmp-X.Y.Z

        * Install it by running on the command line in this order:

         > ./configure
         > make
         > sudo make install
         
        > If you want, you can check the installation by running:
         
         > make check

   * NTL: Number Theory Library

        * Download latest version from http://www.shoup.net/ntl/download.html. I chose the .tar.gz:

         > ntl-X.Y.Z.tar.gz
         
        * uncompress and cd into the directory ntl-XXX/src

         > tar xvf ntl-X.Y.Z.tar.gz
         > cd ntl-X.Y.Z/src

        * On the command line run, in this order:
        
         > ./configure NTL_GMP_LIP=on SHARED=on
         > make
         > sudo make install

        * We need to create a symbolic link for the shared library. Run:
        
         > cd /usr/local/lib/

        > Here you should see a file named libntl.so.XX, where XX is a two digit number. Run, replacing the XX by the number:

         > sudo ln -s /usr/local/lib/libntl.so.XX /usr/lib/libntl.so.XX

2. **Required Python packages**
  * Cython: bridge between C++ and Python, essential to build Pyfhel:
        
        > sudo pip install cython

## INSTALLING HELIB, AFHEL & PYFHEL

1. **PULLING HELIB AS SUBMODULE**
   Check the src/HElib folder, and if you don't see any files inside, it means you didn't clone/pull Pyfhel using *--recursive*. To fix  it, run anywhere inside Pyfhel:
    
       > git submodule update --init --recursive       

2. **CONFIGURE**

   Navigate to the src/ folder, and once inside, execute the following command to set up the Makefiles:

       > ./configure

3. **INSTALLING ALL AT ONCE**

    In order to install HElib and Afhel as shared libraries (.so) and Pyfhel as a Python module, the easiest way is to run:

       > sudo make install
       
    If you prefer to install them one by one, you can do:
    
       > sudo make HElib
       > sudo make Afhel
       > sudo make Pyfhel
       
    Each of these lines are equivalent to running *make* and *make install* inside src/HElib/src/, src/Afhel/ and src/Pyfhel/ directories respctively

**FINISHED!** You're good to go! if you want to start using Afhel/Pyfhel, please move back to the README.

----------------------------------------

## UPDATE
   Updating HElib & Afhel can be done with their install commands. In order to update Pyfhel, run inside the src/Pyfhel/ directory:
       
       > sudo make upgrade

----------------------------------------

## CLEAN
   Installation process creates several files that are no longer needed. If you want to erase them, as well as any executable created inside this project (files ending by _\_x_) and any environment files (.aenv, these are very big):
       
       > sudo make clean

----------------------------------------
 
## UNINSTALL
   Uninstalling all components at once is performed by running:
       
       > sudo make uninstall
       
   If you want to uninstall any particular component, navigate to HElib/src/, Afhel/ or Pyfhel/ directories and run that same command.
   
   


