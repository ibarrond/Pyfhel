# --------------------------------- IMPORTS -----------------------------------
# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc
import numpy


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
import sys

LIBS= False
if "--LIBS" in sys.argv:
    LIBS= True
    del sys.argv[sys.argv.index("--LIBS")]

CYTHONIZE= False
if "--CYTHONIZE" in sys.argv:
    CYTHONIZE= True
    del sys.argv[sys.argv.index("--CYTHONIZE")]
    
    
    
# ------------------------------- SETUP CONFIG --------------------------------
# could run setup from anywhere

PYFHEL_PATH = 'Pyfhel'
AFHEL_PATH = os.path.join(PYFHEL_PATH, 'Afhel')
SEAL_PATH = os.path.join(PYFHEL_PATH, 'SEAL', 'SEAL', 'seal')

# ---------------------------- COMPILATION CONFIG -----------------------------
# Including shared libraries
# TODO: include libpython.a only in windows ? " -D MS_WIN64"
libraries = ["seal", "afhel"] if LIBS else []
local_sources = [] if LIBS else scan(SEAL_PATH,
                                     [os.path.join(AFHEL_PATH, 'Afseal.cpp')])

# Compile flags for extensions
language            = "c++"
include_dirs        = [get_python_inc(),numpy.get_include(),
                       PYFHEL_PATH, AFHEL_PATH, SEAL_PATH]
extra_compile_flags = ["-std=c++17", "-O3", "-DHAVE_CONFIG_H"]

# -------------------------------- EXTENSIONS ---------------------------------
ext = ".pyx" if CYTHONIZE else ".cpp"
ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=[os.path.join(PYFHEL_PATH,"Pyfhel"+ext)]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=[os.path.join(PYFHEL_PATH,"PyPtxt"+ext)]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=[os.path.join(PYFHEL_PATH,"PyCtxt"+ext)]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),   
]
if CYTHONIZE:
    from Cython.Build import cythonize
    ext_modules=cythonize(ext_modules)

# -------------------------------- INSTALLER ----------------------------------
setup(
    name            = "Pyfhel",
    version         = "2.0.0a5",
    author          = "Alberto Ibarrondo",
    author_email    = "ibarrond@eurecom.fr",
    description     = "Python for Homomorphic Encryption Libraries",
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords        = "homomorphic encryption cython cryptography",
    license         = "GNU GPLv3",
    url             = "https://github.com/ibarrond/Pyfhel",     
    setup_requires  =["setuptools>=30.0",
                      "numpy>=1.14.0"],
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
    ext_modules=ext_modules,  
    test_suite=os.path.join(PYFHEL_PATH,"test.py"),
)
