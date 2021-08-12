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

from Pyfhel.util cimport SCHEME_t
# ------------------------------- DECLARATION ---------------------------------

cdef class PyPtxt:
    cdef Plaintext* _ptr_ptxt
    cdef Pyfhel _pyfhel
    cdef SCHEME_t _scheme
    cpdef bool is_zero(self)
    cpdef string to_poly_string(self)
    cpdef void save(self, str fileName, str compr_mode=*)
    cpdef void load(self, str fileName, object scheme)
    cpdef bytes to_bytes(self, str compr_mode=*)
    cpdef void from_bytes(self, bytes content, object scheme)