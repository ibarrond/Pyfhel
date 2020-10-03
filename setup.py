# =============================== SETUP.PY =====================================
# This file installs Pyfhel in your Python3 distribution. Use one of the two:
#   > python3 setup.py install
#   > python3 -m pip install .
# PYPI -> https://packaging.python.org/tutorials/packaging-projects/
#   > python3 setup.py sdist
#   > twine upload dist/*
#   > python3 setup.py clean --all

import shutil, glob, fileinput, re, os, sys, sysconfig, platform
from pathlib import Path

# Check that Python version is 3.5+
v_maj, v_min = sys.version_info[:2]
assert (v_maj, v_min) >= (3,5),\
    "Pyfhel requires Python 3.5+ (your version is {}.{}).".format(v_maj, v_min)



# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE= False
if "--CYTHONIZE" in sys.argv:
    CYTHONIZE= True
    del sys.argv[sys.argv.index("--CYTHONIZE")]


# --------------------------- REQUIREMENT IMPORTS ------------------------------
# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc

# Get requirements
with open("requirements.txt") as f:
    requirements = [req for req in f.read().split('\n') if req]
    
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
def scan_cpp(dir, files=[]):
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if os.path.isfile(path) and path.endswith(".cpp"):
            files.append(str(path))
    return files

# List all the .cpp files
local_sources = scan_cpp(SEAL_PATH,[str(AFHEL_PATH / 'Afseal.cpp')])

# Compile arguments for extensions
language            = "c++"
include_dirs        = [get_python_inc(),
                       str(PYFHEL_PATH), str(AFHEL_PATH), str(SEAL_PATH)]
define_macros=[("NPY_NO_DEPRECATED_API", "NPY_1_7_API_VERSION")]
extra_compile_flags = ["-DHAVE_CONFIG_H"]
if platform.system() == 'Windows':
    # Windows' MSVC2019 compiler doesn't have an O3 optimization
    #>https://docs.microsoft.com/en-us/cpp/build/reference/o-options-optimize-code
    extra_compile_flags += ["-O2"]
else:  # Linux, GCC
    extra_compile_flags += ["-std=c++17","-O3"]


print(extra_compile_flags)

# --------------------------- LIBRARY COMPILATION ------------------------------
# Here we compile Afhel (with the backends) and bundle it into a static library
# Dynamic lybraries are much more complex to manage. In case this was necessary:
#> https://github.com/realead/commonso/blob/master/setup.py

# cpplibraries:
cpplibraries = ('Afhel', {'sources': local_sources,
                          'include_dirs':include_dirs,
                          'cflags':extra_compile_flags,
                          'macros':define_macros,})


# -------------------------------- EXTENSIONS ---------------------------------
ext = ".pyx" if CYTHONIZE else ".cpp"
ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=[str(PYFHEL_PATH/("Pyfhel"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=[str(PYFHEL_PATH/("PyPtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=[str(PYFHEL_PATH/("PyCtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language=language,
             extra_compile_args=extra_compile_flags,
         ),   
]
if CYTHONIZE:
    from Cython.Build import cythonize
    ext_modules=cythonize(ext_modules)

# --------------------------------- CLEANER -----------------------------------
# Tired of cleaning all compilation and distribution by hand
from distutils.cmd import Command
class FlushCommand(Command):
    """Custom clean command to tidy up the project root."""
    CLEAN_FILES = './build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')
    user_options = []
    def initialize_options(self):   pass
    def finalize_options(self):     pass
    def run(self):
        here = os.getcwd()
        for path_spec in self.CLEAN_FILES:
            # Make paths absolute and relative to this path
            abs_paths = glob.glob(os.path.normpath(os.path.join(here, path_spec)))
            for path in [str(p) for p in abs_paths]:
                if not path.startswith(here):
                    # Die if path in CLEAN_FILES is absolute + outside this directory
                    raise ValueError("%s is not a path inside %s" % (path, here))
                print('removing %s' % os.path.relpath(path))
                shutil.rmtree(path)

                
# ---------------------------------- NUMPY ------------------------------------
# We need to know the headers of numpy for compilation. For this, we use
#  our own build_ext function (https://stackoverflow.com/questions/54117786)
def my_build_ext(pars):
    # import delayed:
    from setuptools.command.build_ext import build_ext as _build_ext
    # include_dirs adjusted: 
    class build_ext(_build_ext):
        def finalize_options(self):
            _build_ext.finalize_options(self)
            # Prevent numpy from thinking it is still in its setup process:
            # __builtins__.__NUMPY_SETUP__ = False
            import numpy
            self.include_dirs.append(numpy.get_include())
    #object returned:
    return build_ext(pars)

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
    setup_requires  =["setuptools>=45.0",
                      "numpy>=1.16.0"],
    install_requires=requirements,
    classifiers     =[
        "Programming Language :: C++",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: Unix",
        "Operating System :: POSIX",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    zip_safe=False,
    packages=find_packages(),
    ext_modules=ext_modules,  
    test_suite=str(PYFHEL_PATH / "test.py"),
    libraries=[cpplibraries],
    library_dirs=["."],
    cmdclass={'flush': FlushCommand,
              'build_ext' : my_build_ext},
)
