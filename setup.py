## This file installs Pyfhel in your Python3 distribution.
# Use one of the two:
#   > python3 setup.py install
#   > python3 -m pip install .
# PYPI -> https://packaging.python.org/tutorials/packaging-projects/
#   > python3 setup.py sdist
#   > twine upload dist/*
#   > python3 setup.py clean --all

# ==============================================================================
# ============================ INITIALIZATION ==================================
# ==============================================================================

import shutil, glob, fileinput, re, os, sys, sysconfig, platform, subprocess

# Check that Python version is 3.5+
v_maj, v_min = sys.version_info[:2]
assert (v_maj, v_min) >= (3,5),\
    "Pyfhel requires Python 3.5+ (your version is {}.{}).".format(v_maj, v_min)

# Common Paths for this setup
from pathlib import Path
PYFHEL_PATH = Path('Pyfhel')
AFHEL_PATH = PYFHEL_PATH / 'Afhel'
SEAL_PATH = PYFHEL_PATH / 'backend' / 'SEAL'

# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# Get directories for includes of both Python and Numpy
from distutils.sysconfig import get_python_inc

# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE = False
try:
    import cython
    CYTHONIZE = True
except ImportError:
    pass    # Cython not available, reverting to previously cythonized C++ files

# --------------------------- REQUIREMENT IMPORTS ------------------------------
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
    f.write(re.sub(v_init_regex, '"{}"'.format(VERSION), s))

# Including Readme in the module as long description.
with open("README.md", "r") as fh:
    long_description = fh.read()


# ==============================================================================
# ======================== AUXILIARY FUNCS & COMMANDS ==========================
# ==============================================================================
# Generic utlilities that would normally go in a "utils" folder.
# --------------------------- FILE/DIR FINDER RUNNER ---------------------------
def scan_ftypes(folder, ftypes=[], only=None, recursive=True):
    """Scan a folder searching for all files and/or folders ending with ftypes"""
    matches = []
    if recursive:
        for root, dirs, files in os.walk(folder):
            root = Path(root).absolute()
            if only in (None, 'files'):
                matches+=\
                [str(root/f) for ftype in ftypes for f in files if f.endswith(ftype)]
            if only in (None, 'dirs'):
                matches+=\
                [str(root/d) for ftype in ftypes for d in dirs if d.endswith(ftype)]
    else: # just first 
        for file_or_dir in os.listdir(folder):
            f  = (Path(folder) / file_or_dir).absolute()
            if only in (None, 'files') and f.is_file() and f.suffix in ftypes:
                matches+= [str(f)] 
            if only in (None, 'dirs') and f.is_dir() and \
                any([f.name.endswith(ftype) for ftype in ftypes]):
                matches+= [str(f)] 
    return matches

# ----------------------------- SUBPROCESS RUNNER ------------------------------
def run_command(command, **kwargs):
    """Run a command while printing the live output"""
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )
    while True:   # Could be more pythonic with := in Python3.8+
        line = process.stdout.readline()
        if not line and process.poll() is not None: break
        print(line.decode(), end='')
           
# ---------------------------- AUXILIARY CLEANER -------------------------------
# Tired of cleaning all compilation and distribution by hand.
#  Run `python setup.py flush` to clean-up the entire project.
from distutils.cmd import Command
class flush(Command):
    """Custom clean command to tidy up the project root."""
    CLEAN_FILES = '.eggs ./gmon.out ./build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')
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
                if os.path.isfile(path):    os.remove(path)
                else:                       shutil.rmtree(path) 


# ==============================================================================
# ============================ COMPILATION CONFIG ==============================
# ==============================================================================
# Compile arguments for extensions & C/C++ libraries
include_dirs        = [
    get_python_inc(),   str(PYFHEL_PATH),
    str(AFHEL_PATH),    str(SEAL_PATH),
    str(SEAL_PATH / 'native' / 'src' ),
    str(SEAL_PATH / 'thirdparty' / 'msgsl-src' / 'include')]
cmake_built_include_dirs = []
define_macros=[("NPY_NO_DEPRECATED_API", "NPY_1_7_API_VERSION")]
extra_compile_flags = []
if platform.system() == 'Windows':
    # Windows' MSVC2019 compiler doesn't have an O3 optimization
    #>https://docs.microsoft.com/en-us/cpp/build/reference/o-options-optimize-code
    extra_compile_flags += ["/O2", "/openmp"]
elif platform.system() == 'Darwin': # MacOS
    # extra_compile_flags += ["-std=c++17","-O3","-mmacosx-version-min=10.12"]
    raise SystemError("Pyfhel is not supported in MacOS (see issue #59). Please use a Linux VM or Docker.")
else:  # Linux, GCC
    extra_compile_flags += ["-std=c++17","-O3","-fopenmp"]


# ==============================================================================
# ============================== C/C++ LIBRARIES ===============================
# ==============================================================================
# This section is in charge of compiling C/C++ libraries that will be linked to
#  all the Cython extensions. We currently support standard static libraries &
#  cmake-based libraries.
# ---------------------------- LIBRARY BUILDER ---------------------------------
# We create our own build_clib class to handle CMake-based & static libraries.
from setuptools.command.build_clib import build_clib
class super_build_clib(build_clib):
    def build_libraries(self, libraries):
        global cmake_built_include_dirs
        static_libraries = []
        built_libs = []
        # First compile all cmake libraries
        for (lib_name, build_info) in libraries:
            if build_info.get('type') == 'cmake':       # CMake compilation
                build_dir = Path(self.build_clib).absolute() / lib_name
                build_dir.mkdir(parents=True, exist_ok=True)
                source_dir = Path(build_info.get('source_dir')).absolute()
                run_command(['cmake', source_dir], cwd=build_dir)
                run_command(['cmake', '--build',  '.', '-j', '4'], cwd=build_dir)
                built_libs +=\
                    list(Path(build_dir / build_info.get('lib_dir')).absolute().rglob('*.a'))
                cmake_built_include_dirs += [Path(build_dir/d).absolute() \
                    for d in build_info.get('cmake_built_include_dirs',[])]
            elif build_info.get('type') == 'static':    # Standard compilation
                # Linking created cmake-based libraries to new static libraries
                build_info['cflags'] = build_info.get('cflags', []) + \
                    [f'-l{lib}' for lib in built_libs]
                # Adding post-cmake-build include dirs for cmake-created headers
                build_info['include_dirs'] = cmake_built_include_dirs + \
                    build_info.get('include_dirs', [])
                static_libraries += [(lib_name, build_info)]
        # Then compile all other static libraries
        build_clib.build_libraries(self, static_libraries)

# --------------------------- LIBRARY DEFINITION -------------------------------
# We compile/link Afhel & the backend C/C++ libs into static libraries.
#  Dynamic lybraries are much more complex to manage. In case this was necessary:
#> https://github.com/realead/commonso/blob/master/setup.py
cpplibraries = [
    ('SEAL', 
        {'type': 'cmake',  # Custom library building
        # source_dir points to the top CMakeLists.txt directory.
        'source_dir': PYFHEL_PATH / 'backend' / 'SEAL', 
         # lib_dir is the build-relative output dir containing the cmake-built libs
        'lib_dir': Path('lib'),        
         # post_include_dirs have cmake-created headers to include in future compilations 
        'cmake_built_include_dirs': [Path('native') / 'src'],
        'sources': ['Unused']
        }),
    ('Afhel', 
        {'type': 'static', # Standard build_clib
        'sources': [str(AFHEL_PATH / 'Afseal.cpp')],
        'include_dirs': include_dirs,
        'cflags': extra_compile_flags,
        'macros': [],
        }
    ),
]


# ==============================================================================
# ================================ EXTENSIONS ==================================
# ==============================================================================
# These are the Cython/C++ extensions callable from Python. More info:
#   https://cython.readthedocs.io/en/latest/src/userguide/wrapping_CPlusPlus
# ----------------------------- EXTENSION BUILDER ------------------------------
from setuptools.command.build_ext import build_ext
from distutils.errors import *
from distutils.sysconfig import customize_compiler, get_python_version
from distutils.sysconfig import get_config_h_filename
from distutils.dep_util import newer_group
from distutils import log
class super_build_ext(build_ext):
    def finalize_options(self):
        build_ext.finalize_options(self)
        # We need the numpy headers and cmake-built headers for compilation.
        #  We delay it for the setup to raise a nice error if numpy is not found.
        #  https://stackoverflow.com/questions/54117786
        global cmake_built_include_dirs
        import numpy
        self.include_dirs += [numpy.get_include()] + cmake_built_include_dirs
        
    def build_extensions(self):
        # Removing CMake-built libs from linking with Cython extensions if
        #  any static libraries were built in this setup, since the CMake libs
        #  are being linked already to these static libs (must avoid duplication
        #  of declaration). Extension-defined static/shared libs are not affected.
        built_cmake_libs = set([l_name for (l_name, b_info) in cpplibraries \
                                        if b_info.get('type') == 'cmake'])
        built_static_libs = set([l_name for (l_name, b_info) in cpplibraries \
                                        if b_info.get('type') == 'static'])
        libs = set(self.compiler.libraries)
        if (libs & built_static_libs) ^ built_cmake_libs:  
            self.compiler.libraries = list(libs ^ built_cmake_libs)
        build_ext.build_extensions(self)

# --------------------------- EXTENSION DEFINITION -----------------------------
ext = ".pyx" if CYTHONIZE else ".cpp"
ext_modules = [
         Extension(
             name="Pyfhel.Pyfhel",
             sources=[str(PYFHEL_PATH/("Pyfhel"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=[str(PYFHEL_PATH/("PyPtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=[str(PYFHEL_PATH/("PyCtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_flags,
         ),
         Extension(
             name="Pyfhel.PyPoly",
             sources=[str(PYFHEL_PATH/("PyPoly"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_flags,
         ),   
]

# Try cythonizing if cython is available, otherwise do nothing
if CYTHONIZE:
    from Cython.Build import cythonize
    ext_modules=cythonize(ext_modules)


# ==============================================================================
# ============================== SETUP INSTALLER ===============================
# ==============================================================================
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
                      "numpy>=1.16.0",
                      "cmake"],
    install_requires=requirements,
    classifiers     =[
        "Programming Language :: C++",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
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
    # test_suite=str(PYFHEL_PATH / "test.py"),
    libraries=cpplibraries,
    cmdclass={'flush': flush,
              'build_ext' : super_build_ext,
              'build_clib' : super_build_clib},
)
