# Instalation of Afhel
1. **INSTALL HELIB DEPENDENCIES**

   In order to build HElib, you need to have GMP and NTL libraries installed.
   * GMP:  GNU Multiple Precision Arithmetic Library
        * Download GMP from http://www.gmplib.org. On this case I chose the .bz2 file:

         > gmp-X.Y.Z.tar.bz2

        * uncompress and cd into the directory:

         > bzip2 -d gmp-X.Y.Z.tar.bz2
         > tar xvf gmp-X.Y.Z.tar
         > cd gmp-X.Y.Z

        * Install it by running on the command line in this order:

         > ./configure
        
        > If you get error **"...: No usable m4 in $PATH ..."**, install m4 by running `sudo apt-get install m4`

         > make
         > sudo make install
         
        > If you want, you can check the installation by running:
         
         > make check

   * NTL: Number Theory Library

        * Download NTL from http://www.shoup.net/ntl/download.html. I chose the .tar.gz:

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

        > Here you should see an object like libntl.so.XX, where XX is a two digit number. Run, replacing the XX by the number:

         > sudo ln -s /usr/local/lib/libntl.so.XX /usr/lib/libntl.so.XX

2. **INSTALL HELIB**

   Clone the repository from the original source. If you have downloaded Afhel, this may not be neccessary since HElib is included as a submodule. Check the root folder of Afhel, and if you don't see any files inside the HElib folder, run in the root directory:
    
       > git clone https://github.com/shaih/HElib.git

   On the command line run these commands while inside the HElib/src directory:
       
       > make
       > make check

3. **INSTALL BOOST**

   Boost is a C++ library that will allow us to create map objects to store our Cyphertexts. Run:

       > sudo apt-get install libboost-all-dev

4. **INSTALL AFHEL**

     Go inside the Afhel directory and run:

       > make

# Instalation of Pyfhel

5. **INSTALL CYTHON**

    Cython allows us to bridge between the world of C++ and the world of Python. Run:

       > sudo pip install cython
       > sudo pip3 install cython
       
    > Found any issues? maybe you should check if you have installed pip and a developper version of python (We're installing it for both Python2.X and 3.X):

       > sudo apt-get install python-dev
       > sudo apt-get install python-pip
       > sudo apt-get install python3-dev
       > sudo apt-get install python3-pip

6. **INSTALL PYFHEL**

     Get inside the Pyfhel subdirectory and run:

       > sudo python setup.py install
       > sudo python3 setup.py install
       
     Pyfhel is still showing some errors when imported in Python3. For the moment it's better to stick with Pyton2.X


