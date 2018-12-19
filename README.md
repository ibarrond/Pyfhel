# Pyfhel<img width="10%" height="10%" align="right"  src="/docs/_static/logo.png">
[![Build Status](https://travis-ci.org/ibarrond/Pyfhel.svg?branch=master)](https://travis-ci.org/ibarrond/Pyfhel)
[![Documentation](https://img.shields.io/badge/docs-API-blue.svg)](https://ibarrond.github.io/Pyfhel)
[![PyPI version](https://badge.fury.io/py/Pyfhel.svg)](https://badge.fury.io/py/Pyfhel)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://GitHub.com/ibarrond/Pyfhel/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/ibarrond/Pyfhel.svg)](https://github.com/ibarrond/Pyfhel/issues)
[![Python 3](https://pyup.io/repos/github/ibarrond/Pyfhel/python-3-shield.svg)](https://pyup.io/repos/github/ibarrond/Pyfhel/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)



**PY**thon **F**or **H**omomorphic **E**ncryption **L**ibrary/ies, __*VERSION 2*__.

_Note: If you have written any code using Pyfhel, please share it! (feel free to send me a message, I'll credit you for it). This repo is lacking demos, examples and tests. Besides, if you want to join/contribute to develop this library, just [write me!](mailto:ibarrond@eurecom.fr)_
* **_Status_**: ALPHA.
* **_Description_**: Allows ADDITION, SUBSTRACTION, MULTIPLICATION, SCALAR PRODUCT and binary operations (AND, OR, NOT, XOR) over encrypted vectors|scalars of integers|binaries. This library acts as optimized Python API for the most advanced C++ HE libraries.
* **_Language_**: Python (3.4+) & Cython on top of C++17. (_REQUIRED: Python must have been compiled with C++17: g++>=6 | clang++>=5.0, Visual Studio 2017._).
* **_Docs_**: For now, only the API is documented [[link](https://ibarrond.github.io/Pyfhel)]. Examples are soon to follow.
* **_Dependencies_**: There are three possible backends, all of them HE libraries in C++:
   
   1. [SEAL](https://www.microsoft.com/en-us/research/project/simple-encrypted-arithmetic-library/) (no external dependencies). _Version 2 of Pyfhel is currently only supporting SEAL_.
   2. [HElib](https://github.com/shaih/HElib) (depends on [GMP](http://www.gmplib.org) & [NTL](http://www.shoup.net/ntl/download.html))
   3. [PALISADE](https://git.njit.edu/palisade/PALISADE.git) (no external dependencies)

## Summary
**PY**thon **F**or **H**momorphic **E**ncryption **L**ibraries, **Pyfhel** implements functionalities of multiple Homomorphic Encryption libraries such as addition, multiplication, exponentiation or scalar product in Python. **Pyfhel** uses a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **H**momorphic **E**ncryption **L**ibraries in C++. **Afhel** serves as common API for all three backends. Additionally, this project contains a large series of Demos & Tests for **HElib**|**SEAL**, **Afhel** & **Pyfhel**.

Last but not least, we include Makefiles to compile and install **HElib**, **SEAL** and **Afhel** as shared libraries in Ubuntu, which can then be linked to other C++ programs using the tags `-lhelib`, `-lseal` and `-lafhel`.

## Install & Uninstall
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

You can also install just SEAL and Afhel. Just run `make SEAL|Afhel` in the `Pyfhel` directory and `make install` inside `Pyfhel/Afhel` or `Pyfhel/SEAL` directory respectively. Makefiles also have `clean` and `uninstall` commands, as well as `make sourceFileName_x` command to compile and link a source file (.cpp) with them.
       
 
## Project contents
- `Pyfhel/` contains the source code for Pyfhel, Afhel, SEAL, PALISADE & HElib.

- `docs/` outdated documentation of the project:

     - *Doc.md*: Outdated Essential documentation of the project.
	 - *Doc_API.md*: Outdated comprehensive list of all classes & methods available in Pyfhel.
     - `Helib/`: Up to date docs and images explaining this otherwise undocumented library.

- `Pyfhel/Demos_Tests`, a collection of Demos and Tests. Outdated as of today. Check the `test.py`!
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
