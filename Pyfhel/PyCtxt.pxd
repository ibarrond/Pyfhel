# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Used for all kinds of operations. Includes utility functions
from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import Ciphertext class, original for SEAL
from Pyfhel.Afhel cimport Ciphertext

# Scheme types: UNDEFINED, BFV(INTEGER), CKKS (FRACTIONAL)
from Pyfhel.util.scheme cimport SCHEME_t

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef Ciphertext* _ptr_ctxt
    cdef Pyfhel _pyfhel
    cdef SCHEME_t _scheme
    cpdef int size_capacity(self)
    cpdef int size(self)
    cpdef void save(self, str fileName, str compr_mode=*)
    cpdef void load(self, str fileName, object scheme)
    cpdef bytes to_bytes(self, str compr_mode=*)
    cpdef void from_bytes(self, bytes content, object scheme)
