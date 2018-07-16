# distutils: language = c++

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import the Plaintext from Afhel
from Afhel cimport Plaintext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

cdef class PyPtxt:

    def __cinit__(self, PyPtxt other=None):
        if other:
            self._ptr_ptxt = new Plaintext(deref(other._ptr_ptxt))
        else:
            self._ptr_ptxt = new Plaintext()
            
    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    cpdef bool is_zero(self):
        return self._ptr_ptxt.is_zero()
    
#    cpdef string to_string(self):
#        return self._ptr_ptxt.to_string()
    
    cpdef void save(self, string fileName):
        cdef ofstream outputter
        outputter.open(fileName)
        try:
            self._ptr_ptxt.save(outputter)
        finally:
            outputter.close()

    cpdef void load(self, string fileName):
        cdef ifstream inputter
        inputter.open(fileName)
        try:
            self._ptr_ptxt.load(inputter)
        finally:
            inputter.close()