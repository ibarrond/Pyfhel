from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

# Compile flags for extensions
extra_compile_flags = [ "-std=c++17", "-O3", "-DNDEBUG", "-Wall",\
                        "-Wextra", "-pthread"]

# Set up compiling Environment to Linux 64 bit
#os.environ["CC"] = "x86_64-linux-gnu-g++"
#os.environ["CXX"] = "x86_64-linux-gnu-g++"

# Including Pyfhel Readme in the module.
with open("README.md", "r") as fh:
    long_description = fh.read()

# Installer
setup(
    name            = "Pyfhel",
    version         = "0.0.1",
    author          = "Alberto Ibarrondo",
    author_email    = "ibarrond@eurecom.fr",
    description     = "Python for Homomorphic Encryption Libraries",
    long_description = long_description,
    long_description_content_type="text/markdown",
    keywords        = "homomorphic encryption python cryptography",
    license         = "GNU GPLv3",
    url             = "https://github.com/ibarrond/Pyfhel",     
    install_requires=["cython","numpy"],
    classifiers=(
        "Programming Language :: Python :: 3",
        "Development Status :: Alpha", 
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: Linux",
        "Topic :: Security :: Cryptography",
                                    ),
    ext_modules = cythonize([
         Extension(
             name="Pyfhel",
             sources=["PyPtxt.pyx", "PyCtxt.pyx"],
             libraries=["seal", "afhel"],
             include_dirs=[],
             library_dirs=["/usr/include/python3.6"],
             language="c++17",
             extra_compile_args=extra_compile_flags,
         ),
    ])
)
