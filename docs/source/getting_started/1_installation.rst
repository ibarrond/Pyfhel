Installation
==================

This project has been uploaded to `PyPI <https://pypi.org/project/Pyfhel/>`_. In order to install it from source (*WARNING! it takes several minutes to compile, be patient!*), run:

.. code-block:: bash

    pip install Pyfhel

Locally, you can clone this repository (use `--recursive <https://stackoverflow.com/questions/3796927/how-to-git-clone-including-submodules>`_ to download all submodules) and install it by running:

.. code-block:: bash

    git clone --recursive https://github.com/ibarrond/Pyfhel.git
    pip install .

To uninstall, just run:

.. code-block:: bash

    pip uninstall Pyfhel


**Installing a C/C++ Compiler**

`Pyfhel` requires a C/C++ compiler with C++17 support. We have tested:
- *gcc6* to *gcc12* in Linux/MacOS/Windows WSL. To install:
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
   - Install Visual C++ Build tools (Download `here <https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170>`, guide in `here <https://stackoverflow.com/questions/40504552>`)