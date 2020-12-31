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

cdef class PyPtxt:
    cdef Plaintext* _ptr_ptxt
    cdef Pyfhel _pyfhel
    cdef ENCODING_T _encoding
    cpdef bool is_zero(self) except +
    cpdef string to_poly_string(self) except +
    cpdef void to_file(self, fileName) except +
    cpdef void from_file(self, fileName, encoding) except +
    cpdef void save(self, str fileName) except +
    cpdef void load(self, str fileName, encoding) except +
    cpdef bytes to_bytes(self) except +
    cpdef void from_bytes(self, bytes content, encoding) except +