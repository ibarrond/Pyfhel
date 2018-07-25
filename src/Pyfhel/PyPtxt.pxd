# distutils: language = c++17

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import Plaintext class, original from SEAL
from Afhel cimport Plaintext

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from util.ENCODING_T cimport ENCODING_T
# ------------------------------- DECLARATION ---------------------------------

cdef class PyPtxt:
    cdef Plaintext* _ptr_ptxt
    cdef ENCODING_T _encoding
    cpdef bool is_zero(self)
    cpdef string to_string(self)
    cpdef void save(self, string fileName)
    cpdef void load(self, string fileName)