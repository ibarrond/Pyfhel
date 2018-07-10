# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

from Afseal cimport Plaintext
from Afseal cimport Ciphertext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

cdef class PyCtxt(object):
    cdef Ciphertext* _ptr_ctxt
    def __cinit__(self, PyCtxt other=None):
        if other:
            self._ptr_ctxt = new Ciphertext(deref(other._ptr_ctxt))
        else:
            self._ptr_ctxt = new Ciphertext()
    def __dealloc__(self):
        if self._ptr_ctxt != NULL:
            del self._ptr_ctxt
            
    cpdef size_capacity(self):
        return self._ptr_ctxt.size_capacity()
    
    cpdef size(self):
        return self._ptr_ctxt.size()
    
    cpdef save(self, string fileName):
        cdef ofstream outputter
        outputter.open(fileName)
        try:
            self._ptr_ctxt.save(outputter)
        finally:
            outputter.close()

    cpdef load(self, string fileName):
        cdef ifstream inputter
        inputter.open(fileName)
        try:
            self._ptr_ctxt.load(inputter)
        finally:
            inputter.close()