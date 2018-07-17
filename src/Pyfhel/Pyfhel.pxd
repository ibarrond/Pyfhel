# distutils: language = c++


# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref
cimport cython

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdint cimport int64_t

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport istream, ostream, ifstream, ofstream   

from Afhel cimport Plaintext
from Afhel cimport Ciphertext
from Afhel cimport Afseal

# Import the Cython Plaintext and Cyphertext classes
from PyPtxt cimport PyPtxt
from PyCtxt cimport PyCtxt

# Define Plaintext types
PLAINTEXT_T = (PyPtxt, cython.double, int64_t, np.ndarray[int64_t, ndim=1, mode="c"])
ctypedef fused DOUBLE_INT:
    cython.double
    int64_t