# distutils: language = c++
"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp cimport bool

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport ifstream, ofstream   

# Import the Plaintext from Afhel
from Afhel cimport Plaintext

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyPtxt:
    """Plaintext of Pyfhel. Contains a value/vector of unencrypted ints/doubles.

    This class references SEAL, PALISADE and HElib ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel (SEAL by default).

    Attributes:
        other (:obj:`PyPtxt`, optional): Other PyPtxt to deep copy
    
    """
    def __cinit__(self, PyPtxt other=None):
        if other:
            self._ptr_ptxt = new Plaintext(deref(other._ptr_ptxt))
        else:
            self._ptr_ptxt = new Plaintext()
            
    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    cpdef bool is_zero(self):
        """bool: Flag to quickly check if it is empty"""
        return self._ptr_ptxt.is_zero()
    
    cpdef string to_string(self):
        """string: Polynomial representation of the plaintext"""
        return self._ptr_ptxt.to_string()
    
    cpdef void save(self, string fileName):
        """Save the ciphertext into a file.

        Args:
            fileName: (:obj:`str`) File where the ciphertext will be stored.

        """
        cdef ofstream outputter
        outputter.open(fileName)
        try:
            self._ptr_ptxt.save(outputter)
        finally:
            outputter.close()

    cpdef void load(self, string fileName):
        """Load the plaintext from a file.

        Args:
            fileName: (:obj:`str`) File where the plaintext is retrieved from.

        """
        cdef ifstream inputter
        inputter.open(fileName)
        try:
            self._ptr_ptxt.load(inputter)
        finally:
            inputter.close()
