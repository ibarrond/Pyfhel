# distutils: language = c++
# cython: boundscheck = False
# cython: wraparound = False

"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from util.ENCODING_t import ENCODING_t

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
        self._ptr_ptxt = new Plaintext()
            
    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    @property
    def _encoding(self):
        """returns the encoding type"""
        return ENCODING_t(self._encoding)
    
    @_encoding.setter
    def _encoding(self, new_encoding):
        """Sets Encoding type: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH""" 
        if not isinstance(new_encoding, ENCODING_t):
            raise TypeError("<Pyfhel ERROR> Encoding type of PyPtxt must be ENCODING_t")        
        self._encoding = new_encoding.value
        
    @_encoding.deleter
    def _encoding(self):
        """Sets Encoding to 1-UNDEFINED""" 
        self._encoding = ENCODING_t.UNDEFINED.value
              

        
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
