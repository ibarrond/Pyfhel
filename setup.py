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
from typing import Union, List

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
    
# ----------------------------- NAME & VERSION ---------------------------------
NAME = "Pyfhel"
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

# --------------------------- REQUIREMENT IMPORTS ------------------------------
# Get requirements
with open("requirements.txt") as f:
    requirements = [req for req in f.read().split('\n') if req]

# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE = False
try:
    import cython
    CYTHONIZE = True
except ImportError:
    pass    # Cython not available, reverting to previously cythonized C++ files


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
    CLEAN_FILES = '*/__pycache__ .eggs ./gmon.out ./build ./dist ./*.pyc ./*.tgz ./*.egg-info'.split(' ')
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
# Generic compile & link arguments for extensions. Can be configured
include_dirs        = [
    get_python_inc(),   str(PYFHEL_PATH),
    str(AFHEL_PATH),    str(SEAL_PATH),
    str(SEAL_PATH / 'native' / 'src' ),
    str(SEAL_PATH / 'thirdparty' / 'msgsl-src' / 'include')]
define_macros = [("NPY_NO_DEPRECATED_API", "NPY_1_7_API_VERSION")]
extra_compile_args = [] 

# Help Cython extension linkers find the compiled shared libs
extra_link_args = ["-fopenmp"] + \
    ["-Wl,-rpath=$ORIGIN/."] if platform.system() != 'Windows' else []
libraries = []

# Platform-dependent arguments
if platform.system() == 'Windows':
    # Windows' MSVC2019 compiler doesn't have an O3 optimization
    #>https://docs.microsoft.com/en-us/cpp/build/reference/o-options-optimize-code
    extra_compile_args += ["/O2", "/openmp"]
elif platform.system() == 'Darwin': # MacOS
    # extra_compile_args += ["-std=c++17","-O3","-mmacosx-version-min=10.12"]
    raise SystemError("Pyfhel is not supported in MacOS (see issue #59). Please use a Linux VM or Docker.")
else:  # Linux, GCC
    extra_compile_args += ["-std=c++17","-O3","-fopenmp"]

# Auxiliary arguments. Do not touch! Should start empty
cmake_built_include_dirs = []           
cmake_built_libs = set()
# ==============================================================================
# ============================== C/C++ LIBRARIES ===============================
# ==============================================================================
# This section is in charge of compiling C/C++ libraries that will be linked to
#  all the Cython extensions. We currently support standard static libraries,
#  standard shared libraries & cmake-based libraries. There are several 
#  possible compilation chains:
#  - cmake static/shared libs
#  - standard static/shared libs
#  - cmake shared libs --> standard shared libs
#  - cmake shared libs --> standard static libs
#  - cmake static libs --> first standard shared lib --> other shared libs
# Only the last libs & shared libs in the chain are linked to Cython extensions.
# Note that static libs cannot be linked to other static libs (without hacking).
# ---------------------------- LIBRARY BUILDER ---------------------------------
from setuptools.command.build_clib import build_clib
from setuptools.dep_util import newer_pairwise_group
from distutils import log

class super_build_clib(build_clib):
    def finalize_options(self):
        build_clib.finalize_options(self)
        self.final_lib_folder = get_final_lib_folder()

    def build_libraries(self, libraries):
        """Overriding setuptools/distutils to include cmake libs and shared libs"""
        self.built_libs = {'static':[], 'shared':[]}
        self.static_libs_to_bundle = []
        # Split libraries according to compilation mode
        self.cmake_libs =   [(l_name, b_info) for (l_name, b_info) in libraries\
                                if b_info.get('mode') == 'cmake']
        self.standard_libs =[(l_name, b_info) for (l_name, b_info) in libraries\
                                if b_info.get('mode') in ('standard', None)]
                              
        # CMAKE LIBS BUILD  
        for (lib_name, build_info) in self.cmake_libs:
            self.build_cmake_lib(lib_name, build_info)
        
        # Registering CMake-built libs
        global cmake_built_libs
        cmake_built_libs = set(
            [get_lib_name(lf, 'static') for lf in self.built_libs['static']] + 
            [get_lib_name(lf, 'shared') for lf in self.built_libs['shared']])
        # Link cmake-built libs to subsequent libs
        self.static_libs_to_bundle += self.built_libs['static']

        # Check there are no static -> static chains
        if self.built_libs['static'] and \
            'static' in [b_info.get('type') for (_, b_info) in self.standard_libs]:
            raise AttributeError("Static (cmake-built) libs cannot be linked to other static libs")

        # STANDARD LIBS BUILD
        for (lib_name, build_info) in self.standard_libs:
            
            # Add previously compiled libs to link with next ones
            build_info['libraries'] = build_info.get('libraries', []) + \
                [get_lib_name(lf, 'shared') for lf in self.built_libs['shared']]
            build_info['library_dirs'] = build_info.get('library_dirs', []) + \
                list({str(lf.parent) for lf in self.built_libs['shared']})
            if self.static_libs_to_bundle:  # Link/bundle the static libs only once, as a whole
                # build_info['extra_link_args'] = build_info.get('extra_link_args', []) +\
                #     get_extra_link_args_for_static_bundle(self.static_libs_to_bundle)
                build_info['libraries'] += \
                    [get_lib_name(lf, 'static') for lf in self.static_libs_to_bundle]
                build_info['library_dirs'] = build_info.get('library_dirs', []) + \
                    list({str(lf.parent) for lf in self.static_libs_to_bundle})
                self.static_libs_to_bundle = [] 

            # Compile depending on type
            if   build_info.get('type')=='static':
                self.build_static_lib(lib_name, build_info)
            elif build_info.get('type')=='shared':
                self.build_shared_lib(lib_name, build_info)
            else:
                raise ValueError(f"Wrong {lib_name} library type {build_info.get('type')}")

        # FINALIZE BUILD
        # Copy all static & shared libs (if any) to the extensions build folder & base temp folder
        for lf in self.built_libs['static'] + self.built_libs['shared']:
            shutil_copy_same_ok(lf, self.final_lib_folder)
            shutil_copy_same_ok(lf, self.build_temp)


    def build_cmake_lib(self, lib_name, build_info):
        """Standard CMake build, triggered inside python. Using 4 jobs to build"""
        global cmake_built_include_dirs     # Pass them to extensions too (below)
        
        log.info("building '%s' cmake-based library", lib_name)

        # Build configuration
        build_type = build_info.get('type', 'shared') 
        build_dir = Path(self.build_clib).absolute() / NAME / lib_name
        build_dir.mkdir(parents=True, exist_ok=True)
        source_dir = Path(build_info.get('source_dir')).absolute()
        lib_dir = build_dir / build_info.get('lib_dir')
        
        # Actual build
        run_command(['cmake', source_dir], cwd=build_dir)
        run_command(['cmake', '--build',  '.', '-j', '4'], cwd=build_dir)
        
        # Post build
        self.built_libs[build_type] += \
            list(lib_dir.rglob(f'*{get_lib_suffix(build_type)}'))
        cmake_built_include_dirs += [build_dir / d \
            for d in build_info.get('cmake_built_include_dirs',[])]
            
    def build_static_lib(self, lib_name, build_info):
        """Based on the setuptools build_clib:
        https://github.com/pypa/setuptools/blob/main/setuptools/command/build_clib.py
        """
        log.info("building '%s' static library", lib_name)

        global cmake_built_include_dirs
        # Build Configuration
        sources = build_info.get('sources')
        libraries = build_info.get('libraries', [])
        library_dirs = build_info.get('library_dirs', [])
        extra_link_args = build_info.get('extra_link_args', [])

        if sources is None or not isinstance(sources, (list, tuple)):
            raise DistutilsSetupError("in 'libraries' option (library '%s'), "
             "'sources' must be present and be a list of source filenames" % lib_name)
        sources = list(sources)
        log.info("building '%s' library", lib_name)

        # Make sure everything is the correct type.
        # obj_deps should be a dictionary of keys as sources
        # and a list/tuple of files that are its dependencies.
        obj_deps = build_info.get('obj_deps', dict())
        if not isinstance(obj_deps, dict):
            raise DistutilsSetupError("in 'libraries' option (library '%s'), "
             "'obj_deps' must be a dictionary of type 'source: list'" % lib_name)
        dependencies = []

        # Get the global dependencies that are specified by the '' key.
        # These will go into every source's dependency list.
        global_deps = obj_deps.get('', list())
        if not isinstance(global_deps, (list, tuple)):
            raise DistutilsSetupError("in 'libraries' option (library '%s'), "
             "'obj_deps' must be a dictionary of type 'source: list'" % lib_name)

        # Build the list to be used by newer_pairwise_group
        # each source will be auto-added to its dependencies.
        for source in sources:
            src_deps = [source]
            src_deps.extend(global_deps)
            extra_deps = obj_deps.get(source, list())
            if not isinstance(extra_deps, (list, tuple)):
                raise DistutilsSetupError("in 'libraries' option (library '%s'), "
                 "'obj_deps' must be a dictionary of type 'source: list'" % lib_name)
            src_deps.extend(extra_deps)
            dependencies.append(src_deps)
        expected_objects = \
            self.compiler.object_filenames(sources,output_dir=self.build_temp,)

        if (newer_pairwise_group(dependencies, expected_objects)!= ([], [])):
            # First, compile the source code to object files in the temp directory.
            macros = build_info.get('macros', [])
            include_dirs = build_info.get('include_dirs', []) + cmake_built_include_dirs
            extra_compile_args = build_info.get('extra_compile_args', [])
            self.compiler.compile(
                sources,
                output_dir=self.build_temp,
                macros=macros,
                include_dirs=include_dirs,
                extra_postargs=extra_compile_args,
                debug=self.debug
            )

        # Now "link" the object files together into a static library.
        self.compiler.create_static_lib(
            expected_objects,
            lib_name,
            output_dir=self.build_clib,
            debug=self.debug,
            libraries=libraries,
            library_dirs=library_dirs,
            extra_postargs=extra_link_args,
        )
        # Post build
        prefix = get_lib_prefix()
        lib_file = f"{prefix}{lib_name}{get_lib_suffix('static')}"
        self.built_libs['static'] += [Path(self.build_clib) / lib_file]
        self.static_libs_to_bundle += [Path(self.build_clib) / lib_file]

    def build_shared_lib(self, lib_name, build_info):
        """Based on https://github.com/realead/commonso/blob/master/setup.py"""
        log.info("building '%s' shared library", lib_name)

        # Build configuration
        macros = build_info.get('macros')
        include_dirs = build_info.get('include_dirs') + cmake_built_include_dirs
        extra_compile_args = build_info.get('extra_compile_args')
        libraries = build_info.get('libraries', [])
        library_dirs = build_info.get('library_dirs', [])
        extra_link_args = build_info.get('extra_link_args', [])
        sources = list(build_info.get('sources'))

        # First, compile the source code to object files in the temp directory. 
        objects = self.compiler.compile(
                sources,
                output_dir=self.build_temp,
                macros=macros,
                include_dirs=include_dirs,
                extra_postargs=extra_compile_args,
                debug=self.debug
                )

        # Now link shared object
        language = self.compiler.detect_language(sources)
        lib_file = f"{get_lib_prefix()}{lib_name}{get_lib_suffix('shared')}"

        self.compiler.link_shared_object(
            objects,                     
            lib_file,
            output_dir=self.build_clib,
            libraries=libraries,
            target_lang=language,
            extra_postargs=extra_link_args,
            build_temp=self.build_temp,
            library_dirs=library_dirs,
        )
        # Post build
        self.built_libs['shared'] += [Path(self.build_clib) / lib_file]
        self.static_libs_to_bundle = []

def get_lib_suffix(lib_type: str) -> str:
    if lib_type == 'static':
        if platform.system() == 'Windows':  return '.lib'
        else:                               return '.a'
    else:  # shared
        if platform.system() == 'Windows':  return '.dll'
        else:                               return '.so'

def get_lib_prefix() ->str:
    return 'lib' if platform.system()!='Windows' else ''

def get_lib_name(lib_file: Union[str, Path], lib_type: str) -> str:
    full_name = Path(lib_file).name
    prefix = get_lib_prefix()
    suffix = get_lib_suffix(lib_type)
    return re.sub(prefix + r'(.*)' + suffix, r'\1', full_name)

def get_extra_link_args_for_static_bundle(lib_files: List[Union[str, Path]]) -> List:
    """Add static library to dynamic library for shipping. 
    Warning! Symbols might be duplicated if the dynamic lib depends on the static lib
    """
    lib_files = ([str(Path(lf).absolute()) for lf in lib_files])
    if platform.system() == 'Windows':
        return ['/WHOLEARCHIVE'] + lib_files
    else:
        return ['-Wl,--whole-archive'] + lib_files + ['-Wl,--no-whole-archive']

def get_final_lib_folder():
    """Returns the name of a distutils build directory"""
    f = "{dirname}.{platform}-{version[0]}.{version[1]}"
    dir_name = f.format(dirname='lib',
                    platform=sysconfig.get_platform(),
                    version=sys.version_info)
    return (Path('build') / dir_name / NAME).absolute()

def shutil_copy_same_ok(src: Union[str], dst: Union[str]):
    try:
        shutil.copy(src, dst)
    except shutil.SameFileError:
        pass
# --------------------------- LIBRARY DEFINITION -------------------------------
# We compile/link Afhel & the backend C/C++ libs into static libraries.
#  Shared lybraries are much more complex to manage. In case this was necessary:
#> https://github.com/realead/commonso/blob/master/setup.py
cpplibraries = [
    ('SEAL', 
        {'mode': 'cmake',   # Custom library building
        'type': 'static',   # Info about output files
        # source_dir points to the top CMakeLists.txt directory.
        'source_dir': PYFHEL_PATH / 'backend' / 'SEAL', 
         # lib_dir is the build-relative output dir containing the cmake-built libs
        'lib_dir': Path('lib'),        
         # post_include_dirs have cmake-created headers to include in future compilations 
        'cmake_built_include_dirs': [Path('native') / 'src'],
        'sources': ['Unused, already defined in CMakeLists.txt']
        }),
    ('Afhel', 
        {'mode': 'standard', # Standard build_clib
        'type': 'shared',
        'sources': [str(AFHEL_PATH / 'Afseal.cpp')],
        'include_dirs': include_dirs,
        'extra_compile_args': extra_compile_args,
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
        log.info("cimporting numpy version '%s'", numpy.__version__)
        self.include_dirs += [numpy.get_include()] + cmake_built_include_dirs
        
    def build_extensions(self):
        # Removing CMake-built lib names, adding the real built libs.
        global cpplibraries, cmake_built_libs
        libs = set(self.compiler.libraries)
        cmake_lib_names = set([l_name for (l_name, b_info) in cpplibraries \
                                        if b_info.get('mode') == 'cmake'])
        self.compiler.libraries = list(libs ^ cmake_lib_names | cmake_built_libs)
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
             extra_compile_args=extra_compile_args,
             extra_link_args=extra_link_args,
         ),
         Extension(
             name="Pyfhel.PyPtxt",
             sources=[str(PYFHEL_PATH/("PyPtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_args,
             extra_link_args=extra_link_args,
         ),
         Extension(
             name="Pyfhel.PyCtxt",
             sources=[str(PYFHEL_PATH/("PyCtxt"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_args,
         ),
         Extension(
             name="Pyfhel.PyPoly",
             sources=[str(PYFHEL_PATH/("PyPoly"+ext))],
             include_dirs=include_dirs,
             define_macros=define_macros,
             language="c++",
             extra_compile_args=extra_compile_args,
             extra_link_args=extra_link_args,
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
    name            = NAME,
    version         = VERSION,
    author          = "Alberto Ibarrondo",
    author_email    = "ibarrond@eurecom.fr",
    description     = "Python for Homomorphic Encryption Libraries",
    long_description= long_description,
    long_description_content_type="text/markdown",
    keywords        = "homomorphic encryption cython cryptography",
    license         = "GNU GPLv3",
    url             = "https://github.com/ibarrond/Pyfhel",     
    setup_requires  =["setuptools>=50.0",
                      "numpy>=1.20",
                      "cmake>=3.15",
                      "cython>=0.29"],
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
