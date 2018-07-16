# distutils: language = c++

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

from Afhel cimport Plaintext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

cdef class PyPtxt:
    cdef Plaintext* _ptr_ptxt
    
    cpdef bool is_zero(self)
#    cpdef string to_string(self)
    cpdef void save(self, string fileName)
    cpdef void load(self, string fileName)