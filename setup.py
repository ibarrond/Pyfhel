# =============================== SETUP.PY =====================================
# This file installs Pyfhel in your Python3 distribution. Use:
#   > python3 setup.py install
# PYPI -> https://packaging.python.org/tutorials/packaging-projects/
#   > python3 setup.py sdist
#   > twine upload dist/*
#   > python3 setup.py clean --all

import fileinput, re, os, sys

# Check that Python version is 3.5+
v_maj, v_min = sys.version_info[:2]
assert (v_maj, v_min) >= (3,5),\
    "Pyfhel requires Python 3.5+ (your version is {}.{}).".format(v_maj, v_min)

from pathlib import Path


# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE= False
if "--CYTHONIZE" in sys.argv:
    CYTHONIZE= True
    del sys.argv[sys.argv.index("--CYTHONIZE")]

# Use shared libraries only if installed. Disabled by default. Experimental.
LIBS= False
if "--LIBS" in sys.argv:
    LIBS= True
    del sys.argv[sys.argv.index("--LIBS")]


# -------------------------- INSTALL REQUIREMENTS ------------------------------
# We must install requirements before `setup` because the Cython compilation
#  needs to know the path of numpy library to link with it.
import subprocess, pkg_resources
from pkg_resources import DistributionNotFound, VersionConflict

# Get requirements
with open("requirements.txt") as f:
    requirements = [req for req in f.read().split('\n') if req]

# Check requirements. If a requirement is not met, we install it using pip
try:
    pkg_resources.require(requirements)
except (DistributionNotFound, VersionConflict) as e:
    # A package is not found or the version is too old.
    try:
        subprocess.check_call([sys.executable,"-m","pip","install", str(e.req)])
    except subprocess.CalledProcessError as e:
        raise Exception("Couldn't install required lib {}."%(str(e.req))+\
                        " Try to update pip (for conda, install it manually)")


# --------------------------- REQUIREMENT IMPORTS ------------------------------
# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc
import numpy


# --------------------------------- VERSION ------------------------------------
# Reading version info from Readme and hardcoding it in the __init__.py file
v_readme_regex = r'\[\_*v([0-9]+\.[0-9]+\.[0-9a-z]+)\_*\]'
with open('README.md') as readme:
    VERSION = re.findall(v_readme_regex,readme.read())[0]

v_init_regex = r'\"([0-9]+\.[0-9]+\.[0-9a-z]+)\"'
with open('Pyfhel/__init__.py') as f:
    s = f.read()
with open('Pyfhel/__init__.py', 'w') as f:
    f.write(re.sub(v_init_regex, '"'+VERSION+'"', s))

# Including Readme in the module as long description.
with open("README.md", "r") as fh:
    long_description = fh.read()


# ---------------------------- COMPILATION CONFIG ------------------------------
PYFHEL_PATH = Path('Pyfhel')
AFHEL_PATH = PYFHEL_PATH / 'Afhel'
SEAL_PATH = PYFHEL_PATH / 'SEAL' / 'SEAL' / 'seal'

# Scan a directory searching for all C++ files
def scan(dir, files=[]):
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isfile(path) and path.endswith(".cpp"):
            files.append(str(path))
    return files

# Including shared libraries
# TODO: include libpython.a only in windows ? " -D MS_WIN64"
libraries = ["seal", "afhel"] if LIBS else []
local_sources = [] if LIBS else scan(SEAL_PATH,[str(AFHEL_PATH / 'Afseal.cpp')])

# Compile flags for extensions
language            = "c++"
include_dirs        = [get_python_inc(),numpy.get_include(),
                       str(PYFHEL_PATH), str(AFHEL_PATH), str(SEAL_PATH)]
extra_compile_flags = ["-std=c++17", "-O3", "-DHAVE_CONFIG_H"]


# -------------------------------- EXTENSIONS ---------------------------------
ext = ".pyx" if CYTHONIZE else ".cpp"
ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=[str(PYFHEL_PATH/("Pyfhel"+ext))]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=[str(PYFHEL_PATH/("PyPtxt"+ext))]+local_sources,
             libraries=libraries,
             include_dirs=include_dirs,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=[str(PYFHEL_PATH/("PyCtxt"+ext))]+local_sources,
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
    version         = VERSION,
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
    install_requires=requirements,
    classifiers     =(
        "Programming Language :: C++",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Development Status :: 4 - Beta",
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
    test_suite=str(PYFHEL_PATH / "test.py"),
)
