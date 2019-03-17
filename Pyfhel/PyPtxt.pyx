# distutils: language = c++
#cython: language_level=3, boundscheck=False

"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from .util import ENCODING_t

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyPtxt:
    """Plaintext of Pyfhel. Contains a value/vector of unencrypted ints/doubles.

    This class references SEAL, PALISADE and HElib ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel (SEAL by default).

    Attributes:
        other_ptxt (PyPtxt, optional): Other PyPtxt to deep copy
    
    """
    
    def __cinit__(self, PyPtxt other_ptxt=None, Pyfhel pyfhel=None):
        if (other_ptxt):
            self._ptr_ptxt = new Plaintext(deref(other_ptxt._ptr_ptxt))
            self._encoding = other_ptxt._encoding
            if (other_ptxt._pyfhel):
                self._pyfhel = other_ptxt._pyfhel
        else:
            self._ptr_ptxt = new Plaintext()  
            self._encoding = ENCODING_T.UNDEFINED 
            if (pyfhel):
                self._pyfhel = pyfhel  
                
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
              
        
    @property
    def _pyfhel(self):
        """A pyfhel instance, used for operations"""
        return self._pyfhel
    @_pyfhel.setter
    def _pyfhel(self, new_pyfhel):
        """Sets the pyfhel instance, used for operations""" 
        if not isinstance(new_pyfhel, Pyfhel):
            raise TypeError("<Pyfhel ERROR> new_pyfhel needs to be a Pyfhel class object")       
        self._pyfhel = new_pyfhel 
        
        
    cpdef bool is_zero(self):
        """bool: Flag to quickly check if it is empty"""
        return self._ptr_ptxt.is_zero()
    
    cpdef string to_string(self):
        """string: Polynomial representation of the plaintext"""
        return self._ptr_ptxt.to_string()
    
    cpdef void save(self, str fileName):
        """Save the ciphertext into a file.

        Args:
            fileName: (:obj:`str`) File where the ciphertext will be stored.

        """
        cdef ofstream outputter
        cdef string bFileName = fileName.encode('utf8')
        outputter.open(bFileName)
        try:
            self._ptr_ptxt.save(outputter)
        finally:
            outputter.close()

    cpdef void load(self, str fileName):
        """Load the plaintext from a file.

        Args:
            fileName: (:obj:`str`) File where the plaintext is retrieved from.

        """
        cdef ifstream inputter
        cdef string bFileName = fileName.encode('utf8')
        inputter.open(bFileName)
        try:
            self._ptr_ptxt.load(inputter)
        finally:
            inputter.close()
