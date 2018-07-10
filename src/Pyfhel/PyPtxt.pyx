# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool


cdef class PyPtxt:

    def __cinit__(self, PyPtxt other=None):
        if other:
            self._ptr_ptxt = new Plaintext(deref(other._ptr_ptxt))
        else:
            self._ptr_ptxt = new Plaintext()
            
    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    cpdef is_zero(self):
        return self._ptr_ptxt.is_zero()
    
    cpdef save(self, string fileName):
        cdef ofstream outputter
        outputter.open(fileName)
        try:
            self._ptr_ptxt.save(outputter)
        finally:
            outputter.close()

    cpdef load(self, string fileName):
        cdef ifstream inputter
        inputter.open(fileName)
        try:
            self._ptr_ptxt.load(inputter)
        finally:
            inputter.close()