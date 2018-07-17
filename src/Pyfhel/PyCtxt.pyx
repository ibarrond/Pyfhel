# distutils: language = c++
"""PyCtxt. Ciphertext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import the Plaintext from Afhel
from Afhel cimport Ciphertext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyCtxt:
    """Ciphertext of Pyfhel. Contains a value/vector of encrypted ints/doubles.

    This class references SEAL, PALISADE and HElib ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel. By default, it is SEAL.

    Attributes:
        other (:obj:`PyCtxt`, optional): Other PyCtxt to deep copy
    
    """
    
    def __cinit__(self, PyCtxt other=None):
        if other:
            self._ptr_ctxt = new Ciphertext(deref(other._ptr_ctxt))
        else:
            self._ptr_ctxt = new Ciphertext()
    def __dealloc__(self):
        if self._ptr_ctxt != NULL:
            del self._ptr_ctxt
           
    cpdef int size_capacity(self):
        """int: Maximum size the ciphertext can hold."""
        return self._ptr_ctxt.size_capacity()
     
    cpdef int size(self):
        """int: Actual size of the ciphertext."""
        return self._ptr_ctxt.size()
    
    cpdef void save(self, string fileName):
        """Save the ciphertext into a file.

        Args:
            fileName: (:obj:`str`) File where the ciphertext will be stored.

        """
        cdef ofstream outputter
        outputter.open(fileName)
        try:
            self._ptr_ctxt.save(outputter)
        finally:
            outputter.close()

    cpdef void load(self, string fileName):
        """Load the ciphertext from a file.

        Args:
            fileName: (:obj:`str`) File where the ciphertext is retrieved from.

        """
        cdef ifstream inputter
        inputter.open(fileName)
        try:
            self._ptr_ctxt.load(inputter)
        finally:
            inputter.close()