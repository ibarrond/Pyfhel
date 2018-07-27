# distutils: language = c++17

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Used for all kinds of operations
from Pyfhel cimport Pyfhel

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import Ciphertext class, original for SEAL
from Afhel cimport Ciphertext

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from util.ENCODING_T cimport ENCODING_T
# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef Ciphertext* _ptr_ctxt
    cdef Pyfhel _pyfhel
    cdef ENCODING_T _encoding
    cpdef int size_capacity(self)
    cpdef int size(self)
    cpdef void save(self, string fileName)
    cpdef void load(self, string fileName)