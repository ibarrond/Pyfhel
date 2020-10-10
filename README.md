# Pyfhel [_v2.0.4_] <img width="10%" height="10%" align="right"  src="/docs/_static/logo.png">
[![Build Status](https://travis-ci.org/ibarrond/Pyfhel.svg?branch=master)](https://travis-ci.org/ibarrond/Pyfhel)
[![Documentation Status](https://readthedocs.org/projects/pyfhel/badge/?version=latest)](https://pyfhel.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/Pyfhel.svg)](https://badge.fury.io/py/Pyfhel)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://GitHub.com/ibarrond/Pyfhel/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/ibarrond/Pyfhel.svg)](https://github.com/ibarrond/Pyfhel/issues)
[![Python 3](https://pyup.io/repos/github/ibarrond/Pyfhel/python-3-shield.svg)](https://pyup.io/repos/github/ibarrond/Pyfhel/)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)



**PY**thon **F**or **H**omomorphic **E**ncryption **L**ibraries.

* **_Status_**: BETA.
* **_Description_**: Allows ADDITION, SUBSTRACTION, MULTIPLICATION, SCALAR PRODUCT and binary operations (AND, OR, NOT, XOR) over encrypted vectors|scalars of integers|binaries. This library acts as optimized Python API for the most advanced C++ HE libraries.
* **_Language_**: Python (3.5+) & Cython on top of C++17.

	:warning: _REQUIRED: Python must have been compiled with C++17: g++>=6 | clang++>=5.0, Visual Studio 2017._ :warning:
	
* **_Docs_**: For now, only the API is documented [[link](https://pyfhel.readthedocs.io/en/latest/)]. Examples are soon to follow.
* **_Dependencies_**: There are two possible backends, HE libraries in C++:
   
   1. [SEAL](https://www.microsoft.com/en-us/research/project/simple-encrypted-arithmetic-library/) (no external dependencies).
   2. [PALISADE](https://git.njit.edu/palisade/PALISADE.git) (no external dependencies) __WIP__
   3. ~~[HElib](https://github.com/shaih/HElib) (depends on [GMP](http://www.gmplib.org) & [NTL](http://www.shoup.net/ntl/download.html)) DROPPED~~

## Summary
**PY**thon **F**or **H**momorphic **E**ncryption **L**ibraries, **Pyfhel** implements functionalities of multiple Homomorphic Encryption libraries such as addition, multiplication, exponentiation or scalar product in Python. **Pyfhel** uses a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **H**momorphic **E**ncryption **L**ibraries in C++. **Afhel** serves as common API for all three backends. Additionally, this project contains a large series of Demos & Tests for **HElib**(no longer in use), **SEAL**, **Afhel** & **Pyfhel**.

Last but not least, we include Makefiles to compile and install **HElib**, **SEAL** and **Afhel** as shared libraries in Ubuntu, which can then be linked to other C++ programs using the tags `-lhelib`, `-lseal` and `-lafhel`.

## Install & Uninstall
This project has been uploaded to [PyPI](https://pypi.org/project/Pyfhel/). In order to install it from source (*WARNING! it takes several minutes to compile, be patient!*), run:

	   > pip install Pyfhel

Locally, you can clone this repository (use [`--recursive`](https://stackoverflow.com/questions/3796927/how-to-git-clone-including-submodules) to download all submodules) and install it by running:

	   > git clone --recursive https://github.com/ibarrond/Pyfhel.git
	   > pip install .

To uninstall, just run:
	
	   > pip uninstall Pyfhel
       
### Contribute/Development notice
This is the process to develop/contribute to Pyfhel:
1. _Code a new feature/fix a bug_. Since this project is built using Cython, please refer to [cython documentation](https://cython.readthedocs.io/en/latest/) if you want to help develop it.
2. _Recompile the cython extensions_. After modifying any of the `.pyx`|`pxd` cython files (or the _Afhel_ `.cpp` files) you must recompile the cython files. To do so, run the following command:
```bash
# This will turn `Pyfhel/*.pyx` into the corresponding `Pyfhel/*.cpp` file.
#  Do not edit the `Pyfhel/*.cpp` files directly!
> python3 setup.py --CYTHONIZE --fullname
	Compiling Pyfhel/Pyfhel.pyx because it changed.
	Compiling Pyfhel/PyPtxt.pyx because it depends on ./Pyfhel/iostream.pxd.
	[1/2] Cythonizing Pyfhel/Pyfhel.pyx
	[2/2] Cythonizing Pyfhel/PyPtxt.pyx
	Pyfhel-2.0.2
```

3. _Reinstall Pyfhel locally_. Use either `pip install .` or `python3 setup.py build` (for verbose output and fine control. Run `python3 setup.py --help` for further options).

4. _Test changes locally_. Run the `test.py` file in your environment and make sure all tests are OK:

```bash
python3 Pyfhel/test.py
	test_PyCtxt_creation_deletion (__main__.PyfhelTestCase) ... (0.0s) ...ok
	test_PyPtxt_PyCtxt (__main__.PyfhelTestCase) ... (0.0s) ...ok
	[...]
	test_Pyfhel_5d_save_restore_int (__main__.PyfhelTestCase) ... (1.239s) ...ok

	----------------------------------------------------------------------
	Ran 29 tests in 11.907s

	OK
```
 
5. _Update the version_. To update it, just change the version number on top of this README: Pyfhel [_vA.B.C_]. Bugfixes and minor corrections should increase _C_. New features should increase _B_. Backwards incompatible changes should increase _A_. 

6. _Optional: Update the docs_. WIP (automatic generation with sphinx).

You're ready to go! Just create a pull request to the original repo.

## Project contents
- `docs/` Documentation, generated automatically using sphinx.
- `examples/` Demos and small programs to showcase multiple functionalities. Check `Pyfhel/test.py` for further cases!
- `Pyfhel/` contains the source code for Pyfhel, Afhel, SEAL & PALISADE. 
- `Pyfhel/.Makefiles/Makefile_HElib`, a makefile to compile and install HElib as a dynamic library (`-lhelib`).
- `Pyfhel/.Makefiles/Makefile_SEAL`, a makefile to compile and install SEAL as a dynamic library (`-lseal`).

## Authors & Acknowledgements


- **Authors**: Alberto Ibarrondo [@ibarrond](https://github.com/ibarrond) with Laurent Gomez (SAP) in collaboration with EURECOM ([Melek Onen](http://www.eurecom.fr/~onen/)).
- Latest release: 03/08/2018

This library was created originally for the project "Privacy for Big Data Analytics" in EURECOM. The SW is originally based on **[HElib](https://github.com/shaih/HElib) by Shai Halevi**, with touches from **[HEIDE](https://github.com/heide-support/HEIDE) by Grant Frame**, and performance improvements thanks to **[analysis of addition](https://mshcruz.wordpress.com/2017/05/13/sum-of-encrypted-vectors/) by Matheus S.H. Cruz**. In compliance with their respective Licenses, I name all of them in this section. This project could not be possible without them. For any legal disclaimer, please contact the owner of this repository. Also, the same type of license (GNU GPLv3) applies to Afhel & Pyfhel, as mandated.

## Legal disclaimer

Pyfhel can be used, modified, copied in any way you see fit. This project is Open Source under the GNU GPLv3 License (LICENSE file), therefore developers that use Pyfhel MUST comply with the following:

   1. Acknowledge and mention the original authors of Pyfhel in any derived development, that is, `Ibarrondo, Laurent (SAP) and Onen (EURECOM)`.

   2. Offer the exact same License, allowing legal permission to copy, distribute and/or modify any SW using Pyfhel. Hence, any software using Pyfhel must remain Open Source.
