# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Used for all kinds of operations
from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import Plaintext class, original from SEAL
from Pyfhel.Afhel cimport Plaintext

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util cimport ENCODING_T
# ------------------------------- DECLARATION ---------------------------------

cdef class PyPoly:
    cdef AfsealPoly *afpoly   # Access ready --> handle conversion and keep accessible representation
    cdef Pyfhel *pyfhelobj
    # Error checking in C++

    # Constructor
    PyPoly(Pyfhel) # 
    PyPoly(PyPtxt)
    PyPoly(PyCtxt, index)
    PyPoly(vector[complex], Pyfhel) #? -> optional, add it in Pyfhel.poly_from_coeff_list(vector[complex])
    PyPoly(Pyfhel)

    # encode/decode
    vector[complex] to_coeff_list(void)


    # operators to Pyfhel
    cpdef substract(PyPoly other) --> To Pyfhel
    cpdef add(PyPoly other)--> To Pyfhel
    mult
    inverse
    ...

    # Index accessing -> under the rug of C++ 
    # - TODO later: slicing



    # TODO later: Conversion to PyCtxt/PyPtxt -> 
