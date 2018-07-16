# distutils: language = c++

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

from Afhel cimport Ciphertext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

cdef class PyCtxt(object):
    cdef Ciphertext* _ptr_ctxt
    
    cpdef int size_capacity(self)
    cpdef int size(self)
    cpdef void save(self, string fileName)
    cpdef void load(self, string fileName)