from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import os

os.environ["CC"] = "x86_64-linux-gnu-g++"
os.environ["CXX"] = "x86_64-linux-gnu-g++"

ext_modules = [
    Extension(
        name="Pyfhel",
        sources=["Pyfhel.pyx"],
        include_dirs=[],
        libraries=[ "gmp",
                    "ntl",
                    "fhe",
                    "afhel"
                    ],
        library_dirs=["/usr/include/python2.7",
                      "/usr/include/x86_64-linux-gnu/python2.7",
                    ],
        language="c++",
        extra_compile_args=["-std=c++11",
                            "-DNDEBUG",
                            "-g",
                            "-fwrapv",
                            "-O2",
                            "-Wfatal-errors",
                            "-fPIC",
                            "-pthread", 
                            "-DFHE_THREADS",
                            "-DFHE_DCRT_THREADS", 
                            "-DFHE_BOOT_THREADS"
                            ],
    ),
    Extension(
        name="PyPtxt",
        sources=["PyPtxt.py"],
        include_dirs=[],
        libraries=[],
        library_dirs=[],
        language="python",
    ),
    Extension(
        name="PyCtxt",
        sources=["PyCtxt.py"],
        include_dirs=[],
        libraries=[],
        library_dirs=[],
        language="python",
    )
]

setup(
    name = 'Pyfhel',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules,
)
