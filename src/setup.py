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
with open("../README.md", "r") as fh:
    long_description = fh.read()

# ---------------------------------- OPTIONS ----------------------------------
CYTHONIZE = True
SOURCE = False

if "--CYTHONIZE" in sys.argv:
    CYTHONIZE = True
    del sys.argv[sys.argv.index("--CYTHONIZE")]

if "--SOURCE" in sys.argv:
    SOURCE = True
    del sys.argv[sys.argv.index("--SOURCE")]

# ---------------------------- COMPILATION CONFIG -----------------------------

# Including shared libraries
# TODO: include libpython.a only in windows  " -D MS_WIN64"
libraries = [] if SOURCE else ["seal", "afhel"]
local_sources = scan("SEAL/SEAL/seal", ["Afhel/Afseal.cpp"]) if SOURCE else []

# Compile flags for extensions
language            = "c++17"
include_dirs        = [".",get_python_inc(),numpy.get_include(),"Afhel", "Pyfhel"]
extra_compile_flags = ["-std=c++17", "-O3", "-march=native", 
                       "-DHAVE_CONFIG_H","-DNDEBUG", "-Wall", "-pthread"]

# -------------------------------- EXTENSIONS ---------------------------------
ext = ".pyx" if CYTHONIZE else ".c"

ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=["Pyfhel/Pyfhel"+ext],
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=["Pyfhel/PyPtxt"+ext],
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=["Pyfhel/PyCtxt"+ext],
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
    version         = "0.0.1",
    author          = "Alberto Ibarrondo",
    author_email    = "ibarrond@eurecom.fr",
    description     = "Python for Homomorphic Encryption Libraries",
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords        = "homomorphic encryption cython cryptography",
    license         = "GNU GPLv3",
    url             = "https://github.com/ibarrond/Pyfhel",     
    install_requires=["cython","numpy"],
    classifiers     =(
        "Programming Language :: Python :: 3",
        "Development Status :: Alpha", 
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: Linux",
        "Topic :: Security :: Cryptography",
    ),
   # zip_safe=False,
    packages=find_packages(),   
    package_data={"Pyfhel": ["*.pxd"]},
    ext_modules = ext_modules,  
    test_suite="Pyfhel/test.py",
)
