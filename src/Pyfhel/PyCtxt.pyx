# distutils: language = c++
#cython: language_level=3, boundscheck=False

"""PyCtxt. Ciphertext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import Pyfhel and PyPtxt for operations
from .Pyfhel import Pyfhel
from .PyPtxt import PyPtxt

# Encoding types: 1-UNDEFINED, 2-INTEGER, 3-FRACTIONAL, 4-BATCH
from .util import ENCODING_t

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyCtxt:
    """Ciphertext of Pyfhel. Contains a value/vector of encrypted ints/doubles.

    This class references SEAL, PALISADE and HElib ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel. By default, it is SEAL.

    Attributes:
        other (PyCtxt, optional): Other PyCtxt to deep copy.
    
    """
    def __cinit__(self, PyCtxt other_ctxt=None, Pyfhel pyfhel=None):
        if (other_ctxt):
            self._ptr_ctxt = new Ciphertext(deref(other_ctxt._ptr_ctxt))
            self._encoding = other_ctxt._encoding
            if (other_ctxt._pyfhel):
                self._pyfhel = other_ctxt._pyfhel
        else:
            self._ptr_ctxt = new Ciphertext()
            self._encoding = ENCODING_T.UNDEFINED
            if (pyfhel):
                self._pyfhel = pyfhel
            
    def __dealloc__(self):
        if self._ptr_ctxt != NULL:
            del self._ptr_ctxt
            
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
            
            
    def __neg__(self):
        """Negates this ciphertext.
        """
        self._pyfhel.negate(self)
        
    def __add__(self, other):
        """Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Second summand.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.add_encr(self, other)
        elif isinstance(other, PyPtxt):
            self._pyfhel.add_plain(self, other)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be either PyCtxt or PyPtxt")
            
            
    def __sub__(self, other):
        """Substracts this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Substracts with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Substrahend, to be substracted from this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.sub_encr(self, other)
        elif isinstance(other, PyPtxt):
            self._pyfhel.sub_plain(self, other)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
            
                        
    def __mul__(self, other):
        """Multiplies this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Multiplies with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Multiplier, to be multiplied with this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.mult_encr(self, other)
        elif isinstance(other, PyPtxt):
            self._pyfhel.mult_plain(self, other)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
            
                                    
    def __pow__(self, exponent, modulo):
        """Exponentiates this ciphertext to the desired exponent.
        
        Exponentiates to the desired exponent.

        Args:
            exponent (int): Exponent for the power.
        """
        if(exponent==2):
            self._pyfhel.square(exponent)  
        else:
            self._pyfhel.exponentiate(exponent)     
                
                
    def __rshift__(self, k):
        """Rotates this ciphertext k positions.

        Args:
            k (int): Number of positions to rotate.
        """
        self._pyfhel.rotate(self, k)
