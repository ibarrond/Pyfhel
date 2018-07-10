# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

from Afseal cimport Plaintext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

cdef class PyPtxt:
    cdef Plaintext* _ptr_ptxt
    
    cpdef bool is_zero(self)
    cpdef save(self, string fileName)
    cpdef load(self, string fileName)