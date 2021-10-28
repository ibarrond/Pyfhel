# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool
from libcpp.cast cimport dynamic_cast

# Used for all kinds of operations. Includes utility functions
from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import Abstract Ciphertext class
from Pyfhel.Afhel cimport *

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef AfCtxt* _ptr_ctxt
    cdef Pyfhel _pyfhel
    cdef scheme_t _scheme
    cdef backend_t _backend
    cpdef int size(self)
    cpdef void save(self, str fileName, str compr_mode=*)
    cpdef void load(self, str fileName, object scheme)
    cpdef bytes to_bytes(self, str compr_mode=*)
    cpdef void from_bytes(self, bytes content, object scheme)
