# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool
from libcpp.cast cimport dynamic_cast
from libcpp.memory cimport shared_ptr, make_shared, dynamic_pointer_cast as dyn_cast

# Used for all kinds of operations. Includes utility functions
from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.utils.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import Abstract Ciphertext class
from Pyfhel.Afhel.Afhel cimport *

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class PyCtxt:
    cdef shared_ptr[AfCtxt] _ptr_ctxt
    cdef Pyfhel _pyfhel
    cdef scheme_t _scheme
    cdef backend_t _backend
    cdef int _mod_level
    cpdef int size(self)
    cpdef void set_scale(self, double scale)
    cpdef void round_scale(self)
    cpdef void save(self, str fileName, str compr_mode=*)
    cpdef void load(self, str fileName, object scheme=*)
    cpdef bytes to_bytes(self, str compr_mode=*)
    cpdef void from_bytes(self, bytes content, object scheme=*)

# ---------------------------- VECTOR/ARRAY CLASS ------------------------------
cdef extern from "<utility>" namespace "std" nogil:
    vector[void*] move(vector[void*])
