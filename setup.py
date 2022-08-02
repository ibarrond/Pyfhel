"""This file installs Pyfhel in your Python3 distribution.
# Use one of the two:
#   > python3 setup.py install
#   > python3 -m pip install .
# PYPI -> https://packaging.python.org/tutorials/packaging-projects/
#   > python3 setup.py sdist
#   > twine upload dist/*
#   > python3 setup.py clean --all
"""
# ==============================================================================
# ============================ INITIALIZATION ==================================
# ==============================================================================
from typing import Union, List, Dict, Tuple
from pathlib import Path
import sys
import os
import re
import glob
import shutil
import sysconfig
import platform
import subprocess
import toml
from pkg_resources import parse_version as v_parse

# Create Extension modules written in C for Python
from setuptools import setup, Extension, find_packages

# # Check that Python version is 3.7+
# v_maj, v_min = sys.version_info[:2]
# assert (v_maj, v_min) >= (3,7),\
#     "Pyfhel requires Python 3.7+ (your version is {}.{}).".format(v_maj, v_min)

# Get platform system
platform_system = platform.system()
if platform_system == 'Darwin': # MacOS
    raise SystemError("Pyfhel is not supported in MacOS (see issue #59)."
                      "Please use a Linux VM or Docker.")

# Read config file
config = toml.load("pyproject.toml")
project_config = config['project']
project_name = project_config['name']

# -------------------------------- VERSION -------------------------------------
## Uniformize version across the entire project, taking pyproject.toml as truth.
# Reading version from pyproject.toml
VERSION = project_config['version']
def re_sub_file(regex: str, replace: str, filename: str):
    """Replaces all occurrences of regex in filename with re.sub

    Args:
        regex (str): Regular expression to be replaced
        replace (str): Replacement string
        filename (str): File to be modified
    """
    with open(filename) as sub_file:
        file_string = sub_file.read()
    with open(filename, 'w') as sub_file:
        sub_file.write(re.sub(regex, '{}'.format(replace), file_string))

# Writing version in __init__.py and README.md
V_README_REGEX = r'(?<=\* \*\*_Version_\*\*: )[0-9]+\.[0-9]+\.[0-9a-z]+'
V_INIT_REGEX = r'(?<=__version__ = \")[0-9]+\.[0-9]+\.[0-9a-z]+(?=\")'
re_sub_file(regex=V_README_REGEX, replace=VERSION, filename='README.md')
re_sub_file(regex=V_INIT_REGEX, replace=VERSION, filename='Pyfhel/__init__.py')


# -------------------------------- OPTIONS -------------------------------------
# Compile cython files (.pyx) into C++ (.cpp) files to ship with the library.
CYTHONIZE = False
try:
    from Cython.Build import cythonize
    CYTHONIZE = True
except ImportError:
    pass    # Cython not available, reverting to previously cythonized C++ files

# Config to run coverage tests, if there is a .cov file in the base dir.
COVERAGE = False
if '.cov' in os.listdir():
    print("  [COVERAGE=True] `.cov` file detected. Building with coverage support.")
    COVERAGE = True

# ==============================================================================
# ======================== AUXILIARY FUNCS & COMMANDS ==========================
# ==============================================================================
# Generic utlilities that would normally go in a "utils" folder.
# -------------------------- CONFIG AUXILIARIES --------------------------------
def _pl(args: List[Union[str,dict]]) -> List[str]:
    """_pl: Instantiates platform-dependent args based on current platform.
    It takes the dict elements `el` in args and replaces them by `el[platform_system]"""
    args_pl = []
    for arg in args:
        if isinstance(arg, dict):
            if platform_system in arg:      # A platform-dependent arg
                args_pl += arg[platform_system]
        else:   args_pl.append(arg)
    return args_pl

def _path(args: List[str], base_dir=None) -> List[Path]:
    """_path: Turns all string elements into absolute paths with pathlib.Path"""
    base_dir = Path('') if base_dir is None else base_dir
    return  [(base_dir/arg).absolute().as_posix() if isinstance(arg, (str, Path)) else arg for arg in args]

def _tupl(args: List[List[str]]) -> List[Tuple[str, str]]:
    """_tupl: Picks elements and turns them into tuples"""
    return  [tuple(arg) for arg in args]
# --------------------------- FILE/DIR FINDER ----------------------------------
def scan_ftypes(folder: Union[str, Path],   ftypes: List[str],
                only: str=None,             recursive: bool=True):
    """Scan a folder searching for files and/or folders ending with the strings in ftypes.

    If only is 'dirs' or 'files', returns only directories or files respectively"""
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
            f_obj = (Path(folder) / file_or_dir).absolute()
            if only in (None, 'files') and f_obj.is_file() and f_obj.suffix in ftypes:
                matches+= [str(f_obj)]
            if only in (None, 'dirs') and f_obj.is_dir() and \
                any([f_obj.name.endswith(ftype) for ftype in ftypes]):
                matches+= [str(f_obj)]
    return matches

def shutil_copy_same_ok(src_list: List[Union[str, Path]], dst: Union[str, Path]):
    """Copy file, avoid error if it is the same file"""
    if not Path(dst).exists() or not Path(dst).is_dir():
        Path(dst).mkdir(parents=True)
    for src in src_list:
        try:
            shutil.copy(src, dst)
        except shutil.SameFileError:
            pass

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
        if not line and process.poll() is not None:
            break
        print(line.decode(), end='')

# ---------------------------- AUXILIARY CLEANER -------------------------------
# Tired of cleaning all compilation and distribution by hand.
#  Run `python setup.py flush` to clean-up the entire project.
from distutils.cmd import Command
class FlushCommand(Command):
    """Custom clean command to tidy up the project root."""
    CLEAN_FILES = "*/__pycache__ .eggs ./gmon.out ./build ./.pytest_cache "\
                  "./dist ./*.pyc ./*.tgz ./*.egg-info Pyfhel/*.pyd coverage.xml ./htmlcov **/__pycache__ "\
                  "Pyfhel/*.lib Pyfhel/*.dll Pyfhel/*.exp .coverage".split(" ")
    CLEAN_GITIGNORES = ["Pyfhel/backend/SEAL"]
    user_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
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
                if os.path.isfile(path):
                    os.remove(path)
                else:
                    shutil.rmtree(path)
        # Remove .gitignore files
        for git_repo in self.CLEAN_GITIGNORES:
            print('Emptying gitignored files in repo %s' % os.path.relpath(git_repo))
            run_command(['git', 'clean', '-dfX'], cwd=Path(git_repo).absolute())


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
# All built libs are linked to the extensions.
# Note that static libs cannot be linked to other static libs (without hacking).

# Libs built will be registered here to be injected into extensions.
built_libs = {}

# ----------------------------- LIBRARY CONFIG ---------------------------------
cpplibraries = []
for lib_name, lib_conf in config.pop('cpplibraries', {}).items():
    if lib_conf.get('mode') == 'cmake':
        cpplibraries.append(
            (lib_name,
            {'mode':                lib_conf.get('mode'),
            'lib_type':             lib_conf.get('lib_type', 'shared'),
            'source_dir':           Path(lib_conf.get('source_dir')).absolute(),
            'include_dirs':         _path(lib_conf.get('include_dirs', [])),
            'built_library_dir':    lib_conf.get('built_library_dir', 'lib'),
            'built_include_dirs':   lib_conf.get('built_include_dirs', []),
            'cmake_opts':           lib_conf.get('cmake_opts', {}),
            'sources':              [],  # Unused
            })
        )
    else: # lib_conf.get('mode') == 'standard'
        cpplibraries.append(
            (lib_name,
            {'mode':                lib_conf.get('mode'),
            'lib_type':             lib_conf.get('lib_type', 'shared'),
            'sources':              _path(_pl(lib_conf.get('sources', []))),
            'include_dirs':         _path(_pl(lib_conf.get('include_dirs', []))),
            'extra_compile_args':   _pl(lib_conf.get('extra_compile_args',[])),
            'extra_link_args':      _pl(lib_conf.get('extra_link_args',[])),
            'macros':               _tupl(_pl(lib_conf.get('define_macros', []))),
            'libraries':            _pl(lib_conf.get('libraries', [])),
            'library_dirs':         _path(_pl(lib_conf.get('library_dirs', []))),
            })
        )

# ------------------------ BUILT DEPENDENCY RESOLVER ---------------------------
def _resolve_built_deps(lib_name: str, lib_conf: Dict) -> Tuple[str, Dict]:
    """Resolve dependencies for a given library by checking built_libs"""
    global built_libs
    for lib in lib_conf.get('libraries'):       # Check if lib is already built
        # LINK to the correct libraries. Standard libs are linked correctly by default
        if built_libs.get(lib,{}).get('mode') == 'cmake':
            # Check there are no static -> static chains
            if lib_conf.get('lib_type')==built_libs[lib].get('lib_type')=='static':
                raise TypeError("Static (cmake-built) libs cannot be linked to other static libs")
            # Resolve real libraries
            lib_conf['libraries'].remove(lib)
            lib_conf['libraries'].extend(built_libs[lib]['built_libraries'])

            # INCLUDE the built and compilation headers
            lib_conf['include_dirs'].extend(built_libs[lib]['built_include_dirs'])
            lib_conf['include_dirs'].extend(built_libs[lib]['include_dirs'])

            # Add the real library dirs
            lib_conf['library_dirs'].extend(list(set(
                [Path(l).parent.absolute().as_posix() \
                    for l in built_libs[lib]['built_lib_files']])))

        elif built_libs.get(lib,{}).get('mode') == 'standard':
            # INCLUDE the compilation headers
            lib_conf['include_dirs'].extend(built_libs[lib]['include_dirs'])

    return lib_name, lib_conf

# ---------------------------- LIBRARY BUILDER ---------------------------------
from setuptools.command.build_clib import build_clib
from distutils import log

class SuperBuildClib(build_clib):
    def finalize_options(self):
        build_clib.finalize_options(self)
        self.final_lib_folder = os.path.join(
            self.build_temp.replace("temp.", "lib."), project_name)

    def build_libraries(self, libraries):
        """Overriding setuptools/distutils to include cmake libs and shared libs"""
        global built_libs 
        
        # Split libraries according to compilation mode
        self.cmake_libs =   [(l_name, b_info) for (l_name, b_info) in libraries\
                                if b_info.get('mode') == 'cmake']
        self.standard_libs =[(l_name, b_info) for (l_name, b_info) in libraries\
                                if b_info.get('mode') in ('standard', None)]
                              
        # CMAKE LIBS BUILD
        for (lib_name, build_info) in self.cmake_libs:
            self.build_cmake_lib(lib_name, build_info)

        # STANDARD LIBS BUILD
        for (lib_name, build_info) in self.standard_libs:
            
            # Resolve dependencies with built libs
            lib_name, build_info = _resolve_built_deps(lib_name, build_info)

            # Compile depending on type
            if build_info.get('lib_type')   == 'static':
                self.build_static_lib(lib_name, build_info)
            elif build_info.get('lib_type') == 'shared':
                self.build_shared_lib(lib_name, build_info)
            else:
                raise ValueError(f"Wrong {lib_name} library type {build_info.get('lib_type')}")

        # FINALIZE BUILD
        # Copy all static & shared libs (if any) to the extensions build folder
        for lib in built_libs:
            shutil_copy_same_ok(built_libs[lib]['built_lib_files'], self.final_lib_folder)
            shutil_copy_same_ok(built_libs[lib]['built_lib_files'], self.build_temp)


    def build_cmake_lib(self, lib_name, build_info, n_jobs=4):
        """Standard CMake build, triggered inside python. Using n_jobs to build"""
        global built_libs

        log.info("building '%s' cmake-based library", lib_name)
        # Build configuration
        build_type = build_info.get('lib_type') 
        build_dir = Path(self.build_clib).absolute() / project_name / lib_name
        build_dir.mkdir(parents=True, exist_ok=True)
        source_dir = build_info.get('source_dir')
        cmake_opts = build_info.get('cmake_opts')

        # Actual build
        self.run_cmake_cli(source_dir, build_dir, cmake_opts)
        
        # Post build -> register as built lib/s
        lib_dir = build_dir / build_info.get('built_library_dir')
        built_lib_files = list(lib_dir.rglob(f'*{get_lib_suffix(build_type)}'))
        lib_file_to_name = \
            lambda f: re.sub(f"{get_lib_prefix()}(.*){get_lib_suffix(build_type)}", r"\1", str(f))
        build_info.update({
            'built_lib_files': built_lib_files,
            'built_libraries': [lib_file_to_name(Path(f).name) for f in built_lib_files],
            'built_include_dirs':  _path(build_info.get('built_include_dirs'), base_dir=build_dir),
        })
        built_libs.update({lib_name: build_info})

        
    def build_static_lib(self, lib_name, build_info):
        """Based on the setuptools build_clib:
        https://github.com/pypa/setuptools/blob/main/setuptools/command/build_clib.py
        """
        global built_libs

        log.info("building '%s' static library", lib_name)
        # First, compile the source code to object files in the temp directory.
        sources = build_info.get('sources')
        expected_objects = \
            self.compiler.object_filenames(sources,output_dir=self.build_temp,)
        self.compiler.compile(
            sources             = sources,
            output_dir          = self.build_temp,
            macros              = build_info['macros'],
            include_dirs        = build_info['include_dirs'],
            extra_postargs      = build_info['extra_compile_args'],
            debug               = self.debug
        )

        # Now "link" the object files together into a static library.
        self.compiler.create_static_lib(
            expected_objects,
            lib_name,
            output_dir          = self.build_clib,
            libraries           = build_info['libraries'],
            library_dirs        = build_info['library_dirs'],
            extra_postargs      = build_info['extra_link_args'],
            debug               = self.debug,
        )
        # Post build -> register by adding to built_libs
        lib_file = f"{get_lib_prefix()}{lib_name}{get_lib_suffix('static')}"
        build_info.update({
            'built_lib_files': [str(Path(self.build_clib).absolute() / lib_file)]
        })
        built_libs.update({lib_name: build_info})

    def build_shared_lib(self, lib_name, build_info):
        """Based on https://github.com/realead/commonso/blob/master/setup.py"""
        global built_libs
        log.info("building '%s' shared library", lib_name)

        if platform_system=='Windows':
            self.build_mocked_cmake_lib(lib_name, build_info)
            return
        # First, compile the source code to object files in the temp directory. 
        sources = build_info.get('sources')
        objects = self.compiler.compile(
            sources             = sources,
            output_dir          = self.build_temp,
            macros              = build_info['macros'],
            include_dirs        = build_info['include_dirs'],
            extra_postargs      = build_info['extra_compile_args'],
            debug               = self.debug
            )

        # Now link shared object
        language = self.compiler.detect_language(sources)
        lib_file = f"{get_lib_prefix()}{lib_name}{get_lib_suffix('shared')}"

        self.compiler.link_shared_object(
            objects,                     
            lib_file,
            output_dir          = self.build_clib,
            target_lang         = language,
            libraries           = build_info['libraries'],
            library_dirs        = build_info['library_dirs'],
            extra_postargs      = build_info['extra_link_args'],
            build_temp          = self.build_temp,
        )
        # Post build
        build_info.update({
            'built_lib_files': [str(Path(self.build_clib).absolute() / lib_file)]
        })
        built_libs.update({lib_name: build_info})

    def build_mocked_cmake_lib(self, lib_name, build_info):
        '''Replicate the "build_shared_lib" function using CMake. 
        
        Populate a mock CMakeLists.txt to perform the exact same compilation and
        linking, then execute it. Only necessary when creating a dynamic library
        in Windows, to automatically export all the symbols exposed in it.
        '''
        global built_libs

        # Create cmake project and CMakeLists.txt
        # Build configuration
        build_dir = Path(self.build_temp).absolute() / project_name / f"cmake_{lib_name}"
        build_dir.mkdir(parents=True, exist_ok=True)
        source_dir = '.'
        
        with open(build_dir/"CMakeLists.txt", 'w') as f:
            f.write("cmake_minimum_required(VERSION 3.8)\n")
            f.write(f"project(mocked_cmake_shared_lib_{lib_name})\n")

            # Export all symbols in dll --> This is why Windows needs CMake
            f.write("set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)\n")

            # Output files to a fixed directory
            output_dir = Path(self.build_temp).absolute().as_posix()
            f.write(f"set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $<1:{output_dir}>)\n") # Linux
            f.write(f"set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $<1:{output_dir}>)\n") # Windows
            f.write(f"set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY $<1:{output_dir}>)\n") # Windows
 
            # Add all compile/link options sequentially
            extra_c_args = ' '.join(build_info['extra_compile_args'])
            if extra_c_args:
                f.write(f"add_compile_options({extra_c_args})\n")
            for d in build_info['include_dirs']:
                f.write(f"include_directories({d})\n")
            macros = [f"-d{m[0]}={m[1]}" for m in build_info['macros']]
            if macros:
                f.write(f"add_compile_options({' '.join(macros)})\n")
            extra_l_args = ' '.join(build_info['extra_link_args'])
            if extra_l_args:
                f.write(f"add_link_options({extra_l_args})\n")
            lib_type = build_info['lib_type'].upper()
            sources = ' '.join(build_info['sources'])
            f.write(f"add_library({lib_name} {lib_type} {sources})\n")
            lib_paths = ' '.join([str(p) for p in build_info['library_dirs']])
            if build_info['libraries']:
                lib_cmake_var_names = [cmake_varify_lib_name(l)
                                  for l in build_info['libraries']]
                for l, lib_cmake_var in zip(build_info['libraries'], lib_cmake_var_names):
                    f.write(f"find_library({lib_cmake_var} {l} PATHS {lib_paths})\n")
                lib_cmake_vars = ' '.join([f"${{{var}}}" for var in lib_cmake_var_names])
                f.write(f"target_link_libraries({lib_name} {lib_cmake_vars})\n")
            # TODO: add args from standard compilation (self.compiler)

        # Build cmake project
        self.run_cmake_cli(source_dir, build_dir)

        # Post build
        lib_files = [lf.absolute() for lf in
                     Path(output_dir).glob(f'{get_lib_prefix()}{lib_name}*')]
        build_info.update({'built_lib_files': lib_files})
        built_libs.update({lib_name: build_info})

    def run_cmake_cli(self, source_dir, build_dir, cmake_opts={}, n_jobs=4):
        """Runs `cmake` and `cmake --build` on selected directories."""
        #TODO: change n_jobs to max number of processors
        # Check cmake version
        cmake_ver_str = subprocess.run(['cmake', '--version'], 
                        check=True, capture_output=True, text=True).stdout
        cmake_ver = v_parse(re.search(r'version (\d+\.\d+\.\d+)', cmake_ver_str).group(1))

        cmake_cli_opts = []
        # Parse CMake options
        cmake_config = cmake_opts.pop('CMAKE_BUILD_TYPE', 'Release')
        for k, v in cmake_opts.items():
            cmake_cli_opts.append(f"-D{k}={v}")

        # Run cmake to configure build
        if cmake_ver >= v_parse('3.14'):
            run_command(['cmake', '-S', source_dir, '-B', build_dir] + cmake_cli_opts
            , cwd=build_dir)
        else:
            run_command(['cmake', source_dir] + cmake_cli_opts, cwd=build_dir)

        # Run compilation with j jobs. Set "Release" build in Windows.
        run_command(['cmake', '--build',  '.', '-j', str(n_jobs)] +\
                    (['--config', cmake_config] if platform_system=="Windows" else []), cwd=build_dir)
############################################################################
# Auxiliary methods
def get_lib_suffix(lib_type: str) -> str:
    if lib_type == 'static':
        if platform_system == 'Windows':
            return '.lib'
        else:
            return '.a'
    else:  # shared
        if platform_system == 'Windows':
            return '.dll'
        else:
            return '.so'

def get_lib_prefix() ->str:
    return 'lib' if platform_system!='Windows' else ''

def cmake_varify_lib_name(filename: str) -> str:
    """Turns a filename into a valid CMake variable name"""
    # Create a composed regular expression from a dictionary keys
    sub_table = {
        r'-': r'\_',
        r'\.': r'',
        r' ': r'',
        r' ': r'',
    }
    regex = re.compile("(%s)" % "|".join(map(re.escape, sub_table.keys())))

    # For each match, look-up corresponding value in dictionary
    regex.sub(lambda mo: sub_table[mo.string[mo.start():mo.end()]], filename)    
    return filename.upper()

# def get_extra_link_args_for_static_bundle(lib_files: List[Union[str, Path]]) -> List:
#     """Add static library to dynamic library for shipping. 
#     Warning! Symbols might be duplicated if the dynamic lib depends on the static lib
#     """
#     lib_files = ([str(Path(lf).absolute()) for lf in lib_files])
#     if platform_system == 'Windows':
#         return ['/WHOLEARCHIVE'] + lib_files
#     else:
#         return ['-Wl,--whole-archive'] + lib_files + ['-Wl,--no-whole-archive']


# ==============================================================================
# ================================ EXTENSIONS ==================================
# ==============================================================================
# These are the Cython/C++ extensions callable from Python. More info:
#   https://cython.readthedocs.io/en/latest/src/userguide/wrapping_CPlusPlus
# ----------------------------- EXTENSION BUILDER ------------------------------
from setuptools.command.build_ext import build_ext
class SuperBuildExt(build_ext):
    def finalize_options(self):
        build_ext.finalize_options(self)
        # We need the numpy headers and cmake-built headers for compilation.
        #  We delay it for the setup to raise a nice error if numpy is not found.
        #  https://stackoverflow.com/questions/54117786
        import numpy
        log.info("cimporting numpy version '%s'", numpy.__version__)

        # Resolve built include_dirs and add them to the extension config
        global built_libs
        self.include_dirs += [numpy.get_include()] + \
            [d for conf in built_libs.values() \
                for d in conf['include_dirs']+conf.get('built_include_dirs',[]) \
                if d is not None]
        
    def build_extensions(self):
        # Windows: substituting list of compiler libraries with 'built_lib_files', 
        #  to add the folder containing them (otherwise all libraries are treated
        #  as static and searched with '.lib' extension)
        # Linux: substituting cmake-based lib names with the actual built lib files.
        global built_libs
        libs = set(self.compiler.libraries)
        if platform_system == 'Windows':    
            self.compiler.libraries = [os.path.splitext(l)[0] for (_, b_info) \
                in built_libs.items() for l in b_info.get('built_lib_files',[])]
        else:
            cmake_built_lib_names = set([l for (_, b_info) in built_libs.items() \
                for l in b_info.get('built_libraries',[]) if b_info.get('mode') == 'cmake'])
            cmake_lib_names = set([l_name for (l_name, b_info) in built_libs.items()\
                if b_info.get('mode') == 'cmake'])
            self.compiler.libraries = list(libs ^ cmake_lib_names | cmake_built_lib_names)
        build_ext.build_extensions(self)

    def copy_extensions_to_source(self):
        ## modified to also copy built libs to package dir
        # Copy extensions (default behavior)
        build_ext.build_extensions(self)
        # Copy built libraries
        global built_libs
        package = '.'.join(self.get_ext_fullname(self.extensions[0].name).split('.')[:-1])
        package_dir = self.get_finalized_command('build_py').get_package_dir(package)
        for lib in self.libraries:
            shutil_copy_same_ok(built_libs[lib]['built_lib_files'], package_dir)


# ----------------------------- EXTENSION CONFIG -------------------------------
# Generic compile & link arguments for extensions. Can be modified.
extensions          = config.pop('extensions', {})
config_all          = extensions.pop('config', {})

include_dirs        =  _path(_pl(config_all.get('include_dirs', [])))
define_macros       =  _tupl(_pl(config_all.get('define_macros', [])))
extra_compile_args  =  _pl(config_all.get('extra_compile_args', []))
extra_link_args     =  _pl(config_all.get('extra_link_args', []))
libraries           =  _pl(config_all.get('libraries', []))
library_dirs        =  _path(_pl(config_all.get('library_dirs', [])))

# Add config for coverage tests
if COVERAGE:
    define_macros += [('CYTHON_TRACE', 1), ('CYTHON_TRACE_NOGIL', 1)]

ext_modules = []
for ext_name, ext_conf in extensions.items():
    ext_modules.append(Extension(
        name            = ext_conf.pop('fullname', f"{project_name}.{ext_name}"),
        sources         =      (_pl(ext_conf.pop('sources', []))),
        include_dirs    = _path(_pl(ext_conf.pop('include_dirs', [])))      + include_dirs,
        define_macros   = _tupl(_pl(ext_conf.pop('include_dirs', [])))      + define_macros,
        language        = "c++",
        extra_compile_args=     _pl(ext_conf.pop('extra_compile_args', [])) + extra_compile_args,
        extra_link_args =       _pl(ext_conf.pop('extra_link_args', []))    + extra_link_args,
        libraries       =       _pl(ext_conf.pop('libraries', []))          + libraries,
        library_dirs    = _path(_pl(ext_conf.pop('library_dirs', [])))      + library_dirs,
    ))


# Try cythonizing if cython is available
if CYTHONIZE:
    cython_directives = {
        'embedsignature': True,
        'language_level': 3,
        'cdivision': True,
        'boundscheck': False,
        'c_string_type': 'unicode',
        'c_string_encoding': 'ascii',
        'wraparound': False,
        'initializedcheck': False,
        'linetrace': COVERAGE,
    }
    ext_modules=cythonize(
        ext_modules,
        compiler_directives=cython_directives)

else: # If cython is not available, we use the prebuilt C++ extensions if available
    for ext in ext_modules:
        ext.sources = [s.replace(".pyx", ".cpp") \
            if Path(s.replace(".pyx", ".cpp")).exists() else s for s in ext.sources]

# ==============================================================================
# ============================== SETUP INSTALLER ===============================
# ==============================================================================

# Including Readme in the module as long description.
with open(project_config['readme'], "r") as f:
    long_description = f.read()

setup(
    # Metadata
    name            = project_name,
    version         = VERSION,
    author          = ', '.join([n['name'] for n in project_config['authors']]),
    author_email    = ', '.join([n['email'] for n in project_config['authors']]),
    url             = project_config['urls']['documentation'],
    description     = project_config['description'],
    long_description= long_description,
    long_description_content_type="text/markdown",
    download_url    = project_config['urls']['repository'], 
    classifiers     = project_config['classifiers'],
    platforms       = config['platforms']['platforms'],
    keywords        = ', '.join(project_config['description']),
    license         = project_config['license']['text'],
    # Options
    install_requires=project_config['dependencies'],
    python_requires =project_config['requires-python'],
    zip_safe        =False,
    packages        =find_packages(),
    include_package_data=False,
    ext_modules     =ext_modules,
    libraries       =cpplibraries,
    cmdclass        ={'flush': FlushCommand,
                      'build_ext' : SuperBuildExt,
                      'build_clib' : SuperBuildClib},
)
