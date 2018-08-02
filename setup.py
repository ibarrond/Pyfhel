# --------------------------------- IMPORTS -----------------------------------
# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc
import numpy

import sys

# Scan a directory searching for all C++ files
import os
def scan(dir, files=[]):
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isfile(path) and path.endswith(".cpp"):
            files.append(path)
    return files

# Including Readme in the module as long description.
with open("README.md", "r") as fh:
    long_description = fh.read()

# ---------------------------------- OPTIONS ----------------------------------
SOURCE = False
if "--SOURCE" in sys.argv:
    SOURCE = True
    del sys.argv[sys.argv.index("--SOURCE")]

# ---------------------------- COMPILATION CONFIG -----------------------------

# Including shared libraries
# TODO: include libpython.a only in windows ? " -D MS_WIN64"
libraries = [] if SOURCE else ["seal", "afhel"]
local_sources = scan("Pyfhel/SEAL/SEAL/seal", ["Pyfhel/Afhel/Afseal.cpp"]) if SOURCE else []

# Compile flags for extensions
language            = "c++17"
include_dirs        = [get_python_inc(),numpy.get_include(),
                       ,"Pyfhel/Afhel", "Pyfhel","Pyfhel/SEAL/SEAL/seal"]
extra_compile_flags = ["-std=c++17", "-O3", "-DHAVE_CONFIG_H"]

# -------------------------------- EXTENSIONS ---------------------------------
ext = "" if CYTHONIZE else ".cpp"

ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=["Pyfhel/Pyfhel.pyx"]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=["Pyfhel/PyPtxt.pyx"]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=["Pyfhel/PyCtxt.pyx"]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),   

]

# Convert Cython code into C code
if CYTHONIZE:
    from Cython.Build import cythonize
    ext_modules = cythonize(ext_modules)



# -------------------------------- INSTALLER ----------------------------------
setup(
    name            = "Pyfhel",
    version         = "0.1.1a",
    author          = "Alberto Ibarrondo",
    author_email    = "ibarrond@eurecom.fr",
    description     = "Python for Homomorphic Encryption Libraries",
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords        = "homomorphic encryption cython cryptography",
    license         = "GNU GPLv3",
    url             = "https://github.com/ibarrond/Pyfhel",     
    setup_requires  =["setuptools>=30.0",
                      "cython>=0.25.1"],
    install_requires=["cython>=0.25.1",
                      "numpy>=1.14.0"],
    classifiers     =(
        "Programming Language :: C++",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ),
    zip_safe=False,
    packages=find_packages(),
    package_data={"Pyfhel": ["Pyfhel/*.pxd","README.md"]},
    ext_modules=ext_modules,  
    test_suite="Pyfhel/test.py",
)
