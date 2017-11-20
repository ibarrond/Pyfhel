# Pyfhel

* **_Description_**: Homomorphic Encryption Library for Python. Allows ADDITION, SUBSTRACTION, MULTIPLICATION, SCALAR PRODUCT and binary operations (AND, OR, NOT, XOR, SHIFT & ROTATE) over encrypted vectors of integers/binaries. 
* **_Language_**: Python2.7 on top of C++ (with Cython).
* **_Dependencies_**: [HElib](https://github.com/shaih/HElib), [GMP](http://www.gmplib.org), [NTL](http://www.shoup.net/ntl/download.html)
* **_License_**: [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Summary
**PY**thon **F**or **HEL**ib, **Pyfhel** implements some basic functionalities of HElib as a Homomorphic Encryption library such as sum, mult, or scalar product in Python (currently only for Python2.7). **Pyfhel** allows the use of HElib inside Python and with a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as implementing Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **F**or **HEL**ib in C++. **Afhel** uses an unordered Map to manage HElib Cyphertexts using key-value storage with keys of type _String_. It implements the most important the HElib operations using only the keys for its functions, adding some extra functionalities not present in HElib such as Scalar Product.

Additionally, this project contains a large series of Demos & Tests for **HElib**, **Afhel** & **Pyfhel**.

## Installation
In order to download all the files of this project at once including the dependencies (HElib is set as a submodule), run:

      > git clone --recursive https://github.com/ibarrond/Pyfhel
  
After that, follow the instructions in *INSTALL.md* for the complete installation process. 

## Update, Clean & Uninstall
   Update by running inthe src/ directory:
       
       > sudo make upgrade

   Installation process creates several files that are no longer needed. If you want to erase them, as well as any executable created inside this project (files ending by _\_x_) and any environment files (.aenv, these are very big):
       
       > sudo make clean

   Uninstalling all components at once is performed by running:
       
       > sudo make uninstall
       
   If you want to uninstall any particular component, navigate to HElib/src/, Afhel/ or Pyfhel/ directories and run that same command.
   
## Project contents

- `Docs/` includes all documentation of the project:

     - *Doc.md*: Essential documentation of the project. A must-read.
     - *PyfhelLibrary.md*: Comprehensive list of all classes & methods available in Pyfhel.
 

## Author & Acknowledgements

- Author: Alberto Ibarrondo [@ibarrond](https://github.com/ibarrond) in collaboration with EURECOM ([Melek Onen](http://www.eurecom.fr/~onen/)).
- Latest release: 25/10/2017

This library was created originally for the project "Privacy for Big Data Analytics" in EURECOM. The SW is based on **[HElib](https://github.com/shaih/HElib) by Shai Halevi**, **[HEIDE](https://github.com/heide-support/HEIDE) by Grant Frame**, **[analysis of addition](https://mshcruz.wordpress.com/2017/05/13/sum-of-encrypted-vectors/) by Matheus S.H. Cruz**. In compliance with their respective Licenses, I name all of them in this section. This project could not be possible without them. For any legal disclaimer, please contact me. Also, the same type of license (GNU GLPv3) applies to Afhel & Pyfhel, as mandated.

## Legal disclaimer

Pyfhel can be used modified, copied in any way you see fit. This project is Open Source under the GNU GPLv3 License (LICENSE file), therefore developers that use Pyfhel MUST comply with the following:

   1. Acknowledge and mention the original authors of Pyfhel in any derived development, that is, Alberto Ibarrondo & EURECOM.
   2. Offer the exact same License, allowing legal permission to copy, distribute and/or modify any SW using Pyfhel. Hence, any software using Pyfhel must be Open Source.
