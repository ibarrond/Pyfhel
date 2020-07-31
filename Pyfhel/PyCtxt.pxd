# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Used for all kinds of operations
from Pyfhel.Pyfhel cimport Pyfhel

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport ifstream, ofstream, ostringstream, stringstream

# Import Ciphertext class, original for SEAL
from Pyfhel.Afhel cimport Ciphertext

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util.ENCODING_T cimport ENCODING_T
# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef Ciphertext* _ptr_ctxt
    cdef Pyfhel _pyfhel
    cdef ENCODING_T _encoding
    cpdef int size_capacity(self)
    cpdef int size(self)
    cpdef void save(self, str fileName)
    cpdef string savem(self)
    cpdef void load(self, str fileName, str encoding=*)
    cpdef void loadm(self, bytes content, str encoding=*)