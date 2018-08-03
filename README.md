# Pyfhel [v2]<img width="10%" height="10%" align="right"  src="/docs/logo/logo.png">

* **_Status_**: ALPHA. If you want to join/contribute to develop this library, just [write me!](mailto:ibarrond@eurecom.fr).
* **_Description_**: **PY**thon **F**or **H**omomorphic **E**ncryption **L**ibraries  . Allows ADDITION, SUBSTRACTION, MULTIPLICATION, SCALAR PRODUCT and binary operations (AND, OR, NOT, XOR) over encrypted vectors|scalars of integers|binaries. This library acts as a common Python API for the most advanced C++ HE libraries.
* **_Language_**: Python (3.4+) & Cython on top of C++17. (NOTE: Python must have been compiled with C++17: g++>=6 | clang++>=5.0, Visual Studio 2017).
* **_Dependencies_**: There are three possible backends, all of them HE libraries in C++:
   
   1. [SEAL](https://www.microsoft.com/en-us/research/project/simple-encrypted-arithmetic-library/) (no external dependencies). This version is currently only supporting SEAL.
   2. [HElib](https://github.com/shaih/HElib) (depends on [GMP](http://www.gmplib.org) & [NTL](http://www.shoup.net/ntl/download.html))
   3. [PALISADE](https://git.njit.edu/palisade/PALISADE.git) (no external dependencies)
  
* **_License_**: [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Summary
**PY**thon **F**or **H**momorphic **E**ncryption **L**ibraries, **Pyfhel** implements some basic functionalities of HElib as a Homomorphic Encryption library such as sum, mult, or scalar product in Python. **Pyfhel** uses a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **H**momorphic **E**ncryption **L**ibraries in C++. **Afhel** serves as common API for all three backends. Additionally, this project contains a large series of Demos & Tests for **HElib**|**SEAL**, **Afhel** & **Pyfhel**.

Last but not least, we include Makefiles to compile and install **HElib**, **SEAL** and **Afhel** as shared libraries in Ubuntu, which can then be linked to other C++ programs using the tags `-lhelib`, `-lseal` and `-lafhel`.

## Install & Unistall
This project has been uploaded to [PyPI](https://pypi.org/project/Pyfhel/). In order to install it from source (*WARNING! it takes several minutes to compile, be patient!*), run:

	   > pip install Pyfhel

Locally, you can clone this repository and install it by running:

	   > pip install .

To uninstall, just run:
	
	   > pip uninstall Pyfhel

Alternatively, and only for Ubuntu OS, after cloning you can install and compile all libraries as shared (.so) using the Makefiles on this project. To do so, run inside the `Pyfhel` directory:

	   > ./configure		# Just puts all makefiles in their correct directories
	   > make
	   > sudo make install

You can also install just SEAL and Afhel. Just run `make SEAL|Afhel` in the `Pyfhel` directory and `make install` inside `Pyfhel/Afhel` or `Pyfhel/SEAL` directory respectively. Makefiles also have `clean` and `uninstall` commands, as well as `make sourceFileName_x` command to compile and link a source file with them.
       
 
## Project contents
- `Pyfhel/` contains the source code for Pyfhel, Afhel, SEAL, PALISADE & HElib.

- `docs/` outdated documentation of the project:

     - *Doc.md*: Outdated Essential documentation of the project.
	 - *Doc_API.md*: Outdated comprehensive list of all classes & methods available in Pyfhel.
     - `Helib/`: Up to date docs and images explaining this otherwise undocumented library.

- `Pyfhel/Demos_Tests`, a collection of Demos and Tests.
- `Pyfhel/.Makefiles/Makefile_HElib`, a makefile to compile and install HElib as a dynamic library (`-lhelib`).
- `Pyfhel/.Makefiles/Makefile_SEAL`, a makefile to compile and install SEAL as a dynamic library (`-lseal`).

## Authors & Acknowledgements


- **Authors**: Alberto Ibarrondo [@ibarrond](https://github.com/ibarrond) with Laurent Gomez (SAP) in collaboration with EURECOM ([Melek Onen](http://www.eurecom.fr/~onen/)).
- Latest release: 03/08/2018

This library was created originally for the project "Privacy for Big Data Analytics" in EURECOM. The SW is based on **[HElib](https://github.com/shaih/HElib) by Shai Halevi**, with touches from **[HEIDE](https://github.com/heide-support/HEIDE) by Grant Frame**, and performance improvements thanks to **[analysis of addition](https://mshcruz.wordpress.com/2017/05/13/sum-of-encrypted-vectors/) by Matheus S.H. Cruz**. In compliance with their respective Licenses, I name all of them in this section. This project could not be possible without them. For any legal disclaimer, please contact the owner of this repository. Also, the same type of license (GNU GPLv3) applies to Afhel & Pyfhel, as mandated.

## Legal disclaimer

Pyfhel can be used, modified, copied in any way you see fit. This project is Open Source under the GNU GPLv3 License (LICENSE file), therefore developers that use Pyfhel MUST comply with the following:

   1. Acknowledge and mention the original authors of Pyfhel in any derived development, that is, `Ibarrondo, Laurent (SAP) and Onen (EURECOM)`.

   2. Offer the exact same License, allowing legal permission to copy, distribute and/or modify any SW using Pyfhel. Hence, any software using Pyfhel must remain Open Source.
