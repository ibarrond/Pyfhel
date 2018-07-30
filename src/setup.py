# --------------------------------- IMPORTS -----------------------------------
# Create Extension modules written in C for Python
from setuptools import setup
from setuptools import Extension

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc
from numpy import get_include as get_np_inc

import os

# from sys import prefix
# include libpython.a only in windows  " -D MS_WIN64"
def scandir(dir, files=[]):
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isfile(path) and path.endswith(".cpp"):
            files.append(path)
    return files

# ---------------------------- COMPILATION CONFIG -----------------------------
USE_CYTHON = True   
USE_SHARED_LIBS = False

# Including Readme in the module as long description.
with open("../README.md", "r") as fh:
    long_description = fh.read()

# Including shared libraries
libraries = ["seal", "afhel"] if USE_SHARED_LIBS else []
local_include_dirs = [] if USE_SHARED_LIBS else ["SEAL/SEAL/seal", "Afhel"]

local_sources = [] if USE_SHARED_LIBS else scandir("SEAL/SEAL/seal", ["Afhel/Afseal.cpp"])

# Compile flags for extensions
language            = "c++17"
include_dirs        = [get_python_inc(), get_np_inc()] + local_include_dirs
extra_compile_flags = ["-std=c++17", "-O3", "-march=native", "-DHAVE_CONFIG_H",
                       "-DNDEBUG", "-Wall", "-pthread"]


# -------------------------------- EXTENSIONS ---------------------------------
ext = ".pyx" if USE_CYTHON else ".c"

ext_modules = [
         Extension(
             name="Pyfhel.PyPtxt",
             sources=["Pyfhel/PyPtxt"+ext]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             library_dirs=[],
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=["Pyfhel/PyCtxt"+ext]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             library_dirs=[],
             language=language,
             extra_compile_args=extra_compile_flags,
         ),   
         Extension(
             name="Pyfhel.Pyfhel",
             sources=["Pyfhel/Pyfhel"+ext]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
]

# Convert Cython code into C code
if USE_CYTHON:
    from Cython.Build import cythonize
    ext_modules = cythonize(ext_modules)



# -------------------------------- INSTALLER ----------------------------------
setup(
    name            = "pyfhel",
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
    ext_modules = ext_modules,  
    test_suite="test",
)
