<img width="70%" align="left"  src="/docs/static/logo_title.png"><img width="17%" height="17%" align="right"  src="/docs/static/logo.png">

[![iCodecov](https://codecov.io/gh/ibarrond/Pyfhel/branch/dev/graph/badge.svg?token=S8J8Jlp1Fc)](https://codecov.io/gh/ibarrond/Pyfhel)
[![Documentation Status](https://readthedocs.org/projects/pyfhel/badge/?version=latest)](https://pyfhel.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/Pyfhel.svg)](https://badge.fury.io/py/Pyfhel)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://GitHub.com/ibarrond/Pyfhel/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/ibarrond/Pyfhel.svg)](https://github.com/ibarrond/Pyfhel/issues)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)



**Pyfhel**: **PY**thon **F**or **H**omomorphic **E**ncryption **L**ibraries.

* **_Version_**: 3.3.0
* **_Status_**: STABLE
* **_Description_**: Allows ADDITION, SUBSTRACTION, MULTIPLICATION, SCALAR PRODUCT over encrypted vectors|scalars of integers|binaries. This library acts as optimized Python API for the most advanced C++ HE libraries.
* **_Language_**: Python (3.7+) & Cython on top of C++17.
* **_OS_**: Windows (tested with `MSVC2017`, `MSVC2019`, and `gcc6` for WSL) and Linux (tested on `gcc6`). MacOS not supported.

	:warning: _REQUIRED: An available [compiler supporting C++17](https://en.cppreference.com/w/cpp/compiler_support) ([`g++>=6`] | [`MSVC 2017+`](https://stackoverflow.com/questions/40504552))_ :warning:

* **_Docs_**: Check out our [[documentation in readthedocs](https://pyfhel.readthedocs.io/en/latest/)]. Examples are heavily commented. More examples can be added upon demand!
* **_Dependencies_**: There are two possible backends (both shipped alongside Pyfhel), HE libraries in C++:

   1. [SEAL](https://www.microsoft.com/en-us/research/project/simple-encrypted-arithmetic-library/) (no external dependencies, default).
   2. [PALISADE](https://git.njit.edu/palisade/PALISADE.git) (no external dependencies) __WIP__

## Summary
**PY**thon **F**or **H**omomorphic **E**ncryption **L**ibraries, **Pyfhel** implements functionalities of multiple Homomorphic Encryption libraries such as addition, multiplication, exponentiation or scalar product in Python. **Pyfhel** uses a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **H**omomorphic **E**ncryption **L**ibraries in C++. **Afhel** serves as common API for all backends. Additionally, this project contains a large series of Demos & Tests for **Pyfhel**.

## Install & Uninstall
This project has been uploaded to [PyPI](https://pypi.org/project/Pyfhel/). In order to install it from source (*WARNING! it takes several minutes to compile, be patient!*), run:

	   > pip install Pyfhel

Locally, you can clone this repository (use [`--recursive`](https://stackoverflow.com/questions/3796927/how-to-git-clone-including-submodules) to download all submodules) and install it by running:

	   > git clone --recursive https://github.com/ibarrond/Pyfhel.git
	   > pip install .

To uninstall, just run:

	   > pip uninstall Pyfhel

### Contribute/Development notice
This is the process to develop/contribute:
1. _Code a new feature/fix a bug_. Using [Cython](https://cython.readthedocs.io/en/latest/) for the `.pyx` and `.pxd` extensions, C++ for `Afhel` or Python for examples/tests/other.

2. _Build/Install Pyfhel locally_. Use either `pip install .` or `python3 setup.py build` (for verbose output and fine control. Run `python3 setup.py --help` for further options).

3. _Test changes (requires installing `pytest`)_. Run the tests  locally by executing `pytest .`  in the root directory, and make sure all tests are OK. 
	
   - _Code coverage (requires installing `pytest-cov`)_. Add an empty `.cov` file in the root directory, and build/install the project locally (`pip install .`). To run coverage tests, execute `pytest --cov .` in the root directory, and then `coverage html` to obtain a report.

You're ready to go! Just create a pull request to the original repo.

## Project contents
- `docs/` Documentation, generated automatically using sphinx and pushed to [readthedocs](https://pyfhel.readthedocs.io)
- `examples/` Demos and small programs to showcase multiple functionalities.
- `Pyfhel/` contains the source code for Pyfhel and Afhel.
- `Pyfhel/backend`, underlying C++ libraries SEAL & PALISADE.

## Authors, Citing & Acknowledgements


- **Authors**: [Alberto Ibarrondo](https://scholar.google.com/citations?hl=en&user=hl-5WRQAAAAJ) (IDEMIA & EURECOM) \& [Alexander Viand](https://pps-lab.com/people/alexanderviand/) (ETH Zurich).
- **Original Collaborators**: [Melek Onen](http://www.eurecom.fr/~onen/) (EURECOM) [Laurent Gomez](https://scholar.google.com/citations?user=QJv4B9EAAAAJ) (SAP Labs).

If you wish to cite this work, please use the following BibTeX entry:
```bibtex
  @inproceedings{ibarrondo2021pyfhel,
  title={Pyfhel: Python for homomorphic encryption libraries},
  author={Ibarrondo, Alberto and Viand, Alexander},
  booktitle={Proceedings of the 9th on Workshop on Encrypted Computing \& Applied Homomorphic Cryptography},
  pages={11--16},
  year={2021}
}
```

This library was created originally for the project "Privacy for Big Data Analytics" in EURECOM. For any legal disclaimer, please contact the owner of this repository.

## Legal disclaimer

Pyfhel can be used, modified, copied in any way you see fit. This project is Open Source under the GNU GPLv3 License (LICENSE file), therefore developers that use Pyfhel MUST comply with the following:

   1. Acknowledge and mention the original authors of Pyfhel in any derived development, that is, `Alberto Ibarrondo (IDEMIA & EURECOM) and Alexander Viand (ETH Zurich)` (maybe even cite the paper!).

   2. Offer the exact same License, allowing legal permission to copy, distribute and/or modify any SW using Pyfhel. Hence, **any software using Pyfhel must remain Open Source**.
