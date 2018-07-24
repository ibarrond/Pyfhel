# distutils: language = c++17

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import Ciphertext class, original for SEAL
from Afhel cimport Ciphertext


# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef Ciphertext* _ptr_ctxt
    cpdef int size_capacity(self)
    cpdef int size(self)
    cpdef void save(self, string fileName)
    cpdef void load(self, string fileName)