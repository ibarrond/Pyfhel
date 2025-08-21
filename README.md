<img width="70%" align="left"  src="/docs/static/logo_title.png"><img width="17%" height="17%" align="right"  src="/docs/static/logo.png">

[![iCodecov](https://codecov.io/gh/ibarrond/Pyfhel/branch/master/graph/badge.svg?token=S8J8Jlp1Fc)](https://codecov.io/gh/ibarrond/Pyfhel)
[![Documentation Status](https://readthedocs.org/projects/pyfhel/badge/?version=latest)](https://pyfhel.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/Pyfhel.svg)](https://badge.fury.io/py/Pyfhel)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://GitHub.com/ibarrond/Pyfhel/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/ibarrond/Pyfhel.svg)](https://github.com/ibarrond/Pyfhel/issues)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)


Python library for Addition, Subtraction, Multiplication and Scalar Product over *encrypted* integers (BFV/BGV schemes) and approximated floating point values (CKKS scheme). This library acts as an optimized Python API for C++ Homomorphic Encryption libraries.

|                                            |                                                                                            |
|--------------------------------------------|--------------------------------------------------------------------------------------------|
| :flags: **Language**                       | Python (3.10+), with Cython and C++ ( :warning: _requires a [C++17 compiler][3]_ :warning: ) |
| :computer: **OS**                          | Linux, Windows & MacOS.                                                                    |
| :1234: **Version** | 3.5.0 (stable)                                                                                                     |
| :books: **Docs**                           | In [readthedocs][1]!                                                                       |
| :pencil2: **Demos/Examples**               | [In the docs][4] with the outputs, sources in the [`examples`][2] folder.                  |
| :electric_plug: **Backends**               | [SEAL][5], [OpenFHE (WIP)][6]. Shipped alongside Pyfhel.                                   |
| :construction_worker: **Authors**          | [Alberto Ibarrondo][7] (IDEMIA & EURECOM) and [Alexander Viand][8] (ETH Zurich).           |
| :mortar_board: **Original Collaborators**  | [Melek Onen][9] (EURECOM), [Laurent Gomez][10] (SAP Labs).                                 |
|                                            |                                                                                            |


If you wish to cite Pyfhel in your derived work, please use the following BibTeX entry:
```bibtex
@inproceedings{ibarrondo2021pyfhel,
  title={Pyfhel: Python for homomorphic encryption libraries},
  author={Ibarrondo, Alberto and Viand, Alexander},
  booktitle={Proceedings of the 9th on Workshop on Encrypted Computing \& Applied Homomorphic Cryptography},
  pages={11--16},
  year={2021}
}
```

[1]:https://pyfhel.readthedocs.io/en/latest/
[2]:https://github.com/ibarrond/Pyfhel/tree/master/examples
[3]:https://en.cppreference.com/w/cpp/compiler_support
[4]:https://pyfhel.readthedocs.io/en/latest/_autoexamples/index.html
[5]:https://github.com/microsoft/SEAL/
[6]:https://github.com/openfheorg/openfhe-development
[7]:https://scholar.google.com/citations?hl=en&user=hl-5WRQAAAAJ
[8]:https://pps-lab.com/people/alexanderviand/
[9]:http://www.eurecom.fr/~onen/
[10]:https://scholar.google.com/citations?user=QJv4B9EAAAAJ

  <br />

-------------
[`Install & Uninstall`](#install--uninstall)&ensp; [`Summary`](#summary)&ensp; [`Contributing`](#contributing)&ensp; [`Bugs & Feature Requests`](#bugs--feature-requests)&ensp; [`Legal Disclaimer`](#legal-disclaimer)

-------------
<br />

## Install & Uninstall
To install `Pyfhel` from [PyPI](https://pypi.org/project/Pyfhel/), run (*WARNING! it takes several minutes to compile and install, be patient!*):
```bash
pip install Pyfhel
```

To install the latest version, you can clone this repository with [all the submodules](https://stackoverflow.com/questions/3796927/how-to-git-clone-including-submodules) and install it by running:
```bash
git clone --recursive https://github.com/ibarrond/Pyfhel.git
pip install .
```

To uninstall, just run:
```bash
pip uninstall Pyfhel
```

### With Docker
You can also use Docker to build and run `Pyfhel`. A Dockerfile is provided in the repository, which sets up the necessary environment. Check it up to configure python versions (default 3.12) and virtual environment location (default `/home/venv`). To build the image, just run:
```bash
docker build --tag 'pyfhel-docker' .
```

To run the container interactively, you can use:
```bash
docker run -it pyfhel-docker
```

### Installing a C/C++ Compiler
`Pyfhel` requires a C/C++ compiler with C++17 support. We have tested:
- *gcc6* to *gcc14* in Linux/MacOS/Windows WSL. To install:
   - Ubuntu: `sudo apt install gcc g++`
   - MacOS: `brew install gcc`. MacOS users must also set several environment variables by running:
```bash
        # Brew installs GCC in /opt/homebrew/bin on Apple Silicon and /usr/local/bin on Intel.
        if [[ $(uname -m) = "arm64" ]]; then BREW_GCC_PATH="/opt/homebrew/bin"; else BREW_GCC_PATH="/usr/local/bin"; fi

        # Set CC/CXX environment variables to the most recent GNU GCC
        export CC="$BREW_GCC_PATH/$(ls $BREW_GCC_PATH | grep ^gcc-[0-9] | sort -V -r | head -n 1)"
        export CXX="$BREW_GCC_PATH/$(ls $BREW_GCC_PATH | grep ^g++-[0-9] | sort -V -r | head -n 1)"
        
        # Set MACOSX_DEPLOYMENT_TARGET to avoid version mismatch warnings
        echo "MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion)" >> $GITHUB_ENV
        echo "MACOSX_DEPLOYMENT_TARGET=${{ env.MACOSX_DEPLOYMENT_TARGET }}"
```
- *MSVC2017* and *MSVC2019* in Windows. To install:
   - Install Visual C++ Build tools (Download [here](https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170), guide in [here](https://stackoverflow.com/questions/40504552))

## Summary
**PY**thon **F**or **H**omomorphic **E**ncryption **L**ibraries, **Pyfhel** implements functionalities of multiple Homomorphic Encryption libraries such as addition, multiplication, exponentiation or scalar product in Python. **Pyfhel** uses a syntax similar to normal arithmetics (+,-,\*). This library is useful both for simple Homomorphic Encryption Demos as well as for complex problems such as Machine Learning algorithms.

**Pyfhel** is built on top of **Afhel**, an **A**bstraction **H**omomorphic **E**ncryption **L**ibraries in C++. **Afhel** serves as common API for all backends. Additionally, this project contains a large series of Demos & Tests for **Pyfhel**.

This repository contains:
- `docs/` Documentation, generated automatically using sphinx and pushed to [readthedocs](https://pyfhel.readthedocs.io).
- `examples/` Demos and small programs to showcase multiple functionalities.
- `Pyfhel/` contains the source code for Pyfhel and Afhel.
- `Pyfhel/backend`, underlying C++ libraries SEAL & PALISADE.


## Contributing
This is the standard process to develop/contribute:
1. _Code a new feature/fix a bug_. Using [Cython](https://cython.readthedocs.io/en/latest/) for the `.pyx` and `.pxd` extensions, C++ for `Afhel` or Python for examples/tests/other.

2. _Build/Install Pyfhel locally_. Use `pip install -v -v .` for a verbose installation.

3. _Test changes (requires installing `pytest`)_. Run the tests locally by executing `pytest .`  in the root directory, and make sure all tests pass. 
	
   - _Code coverage (requires installing `pytest-cov`)_. Add an empty `.cov` file in the root directory, and build/install the project locally (`pip install .`). To run coverage tests, execute `pytest --cov .` in the root directory, and then `coverage html` to obtain a report.

You're ready to go! Just create a pull request to the original repo.

## Bugs & Feature Requests
Please fill the [**Bug Report**](https://github.com/ibarrond/Pyfhel/issues/new/choose) template to provide all the essential info to reproduce your issue and solve the problem.

If you wish to have new functionality added to Pyfhel, you are more than welcome to request it via the [**Feature**](https://github.com/ibarrond/Pyfhel/issues/new/choose) template.

## Legal disclaimer
This project is Open Source under the Apache V2 License (LICENSE file). Hence, Pyfhel can be used, modified, and copied freely provided that developers:

   1. Acknowledge and mention the original authors of Pyfhel in any derived development, that is, `Alberto Ibarrondo (IDEMIA & EURECOM) and Alexander Viand (ETH Zurich)` (maybe even cite the paper!).

   2. Maintain the same License, and provide a statement of changes.
      
We encourage **any software using Pyfhel to be Open Source**, for the benefit of everyone using it.
