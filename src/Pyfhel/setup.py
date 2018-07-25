# --------------------------------- IMPORTS -----------------------------------
# Create Extension modules written in C for Python
from setuptools import setup
from setuptools import Extension

# Convert Cython code into C code
from Cython.Build import cythonize

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc
from numpy import get_include as get_np_inc

# from sys import prefix
# include libpython.a only in windows  " -D MS_WIN64"
 
# ---------------------------- COMPILATION CONFIG -----------------------------
# Compile flags for extensions
language            = "c++17"
libraries           = ["seal", "afhel"]
include_dirs        = [get_python_inc(), get_np_inc()]
extra_compile_flags = [ "-std=c++17", "-O3", "-DNDEBUG", "-Wall",\
                        "-Wextra", "-pthread"]

# Including Readme in the module as long description.
with open("README.md", "r") as fh:
    long_description = fh.read()

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
    ext_modules = cythonize([

         Extension(
             name="PyPtxt",
             sources=["PyPtxt.pyx"],
             libraries=libraries,
             include_dirs=include_dirs,
             library_dirs=[],
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="PyCtxt",
             sources=["PyCtxt.pyx"],
             libraries=libraries,
             include_dirs=include_dirs,
             library_dirs=[],
             language=language,
             extra_compile_args=extra_compile_flags,
         ),   
         Extension(
             name="Pyfhel",
             sources=["Pyfhel.pyx"],
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
    ]),
    test_suite="test",
)
