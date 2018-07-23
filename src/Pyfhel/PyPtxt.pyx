# distutils: language = c++
# cython: boundscheck = False
# cython: wraparound = False

"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Encoding types: 1-UNDEFINED, 2-INTEGER, 3-FRACTIONAL, 4-BATCH
from util import ENCODING_T

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
        self._encoding = ENCODING_T.UNDEFINED
        if other:
            self._ptr_ptxt = new Plaintext(deref(other._ptr_ptxt))
        else:
            self._ptr_ptxt = new Plaintext()
            
    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    @property
    def _encoding(self):
        """returns the encoding type"""
        return self.encoding
    
    @_encoding.setter
    def _encoding(self, newEncoding):
        """Sets Encoding type: 1-UNDEFINED, 2-INTEGER, 3-FRACTIONAL, 4-BATCH""" 
        if not isinstance(newEncoding, ENCODING_T):
            raise TypeError("<Pyfhel ERROR> Encoding type of PyPtxt must be a valid ENCODING_T Enum")        
        self.encoding = newEncoding
        
    @_encoding.deleter
    def _encoding(self):
        """Sets Encoding to 1-UNDEFINED""" 
        self.encoding = ENCODING_T.UNDEFINED
        
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
