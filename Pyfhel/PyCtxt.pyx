# distutils: language = c++
#cython: language_level=3, boundscheck=False

"""PyCtxt. Ciphertext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import Pyfhel and PyPtxt for operations
from .Pyfhel import Pyfhel
from .PyPtxt import PyPtxt

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from .util import ENCODING_t

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# Managing paths directly
from pathlib import Path

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyCtxt:
    """Ciphertext of Pyfhel. Contains a value/vector of encrypted ints/doubles.

    This class references SEAL, PALISADE and HElib ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel. By default, it is SEAL.

    Attributes:
        copy_ctxt (PyCtxt, optional): Other PyCtxt to deep copy.
    
    """
    def __cinit__(self,
                  PyCtxt copy_ctxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  encoding=None):
        if (copy_ctxt): # If there is a PyCtxt to copy, override all arguments and copy
            self._ptr_ctxt = new Ciphertext(deref(copy_ctxt._ptr_ctxt))
            self._encoding = copy_ctxt._encoding
            if (copy_ctxt._pyfhel):
                self._pyfhel = copy_ctxt._pyfhel
        
        else:
            self._ptr_ctxt = new Ciphertext()
            if fileName:
                if not encoding:
                    raise TypeError("<Pyfhel ERROR> PyCtxt initialization with loading requires valid encoding")    
                self.from_file(fileName, encoding)
            else:
                self._encoding = to_ENCODING_t(encoding) if encoding else ENCODING_T.UNDEFINED
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
        
    cpdef int size_capacity(self) except +:
        """int: Maximum size the ciphertext can hold."""
        return self._ptr_ctxt.size_capacity()
     
    cpdef int size(self) except +:
        """int: Actual size of the ciphertext."""
        return self._ptr_ctxt.size()

    cpdef void to_file(self, fileName) except +:
        """to_file(Path fileName)
        
        Alias of `save` using Pathlib.
        """
        if isinstance(fileName, Path):
            fileName = str(fileName)
        self.save(fileName)

    cpdef void save(self, str fileName) except +:
        """save(str fileName)
        
        Save the ciphertext into a file. The file can new one or
        exist already, in which case it will be overwriten.

        Args:
            fileName: (:obj:`str`) File where the ciphertext will be stored.
        """
        cdef ofstream* outputter
        cdef string bFileName = fileName.encode('utf8')
        outputter = new ofstream(bFileName, binary)
        try:
            self._ptr_ctxt.save(deref(outputter))
        finally:
            del outputter

    cpdef bytes to_bytes(self) except +:
        """to_bytes()

        Serialize the ciphertext into a binary/bytes string.

        Return:
            * bytes: serialized ciphertext
        """
        cdef ostringstream outputter
        self._ptr_ctxt.save(outputter)
        return outputter.str()

    cpdef void from_file(self, fileName, encoding) except +:
        """from_file(str fileName)
        
        Alias of `load`.
        """
        if isinstance(fileName, Path):
            fileName = str(fileName)
        self.load(fileName, encoding)

    cpdef void load(self, str fileName, encoding) except +:
        """load(self, str fileName)
        
        Load the ciphertext from a file.

        Args:
            fileName: (:obj:`str`) File where the ciphertext is retrieved from.
            encoding: (:obj: `str`) String describing the encoding: 'int' for
                IntegerEncoding (default), 'float'/'fractional'/'double' for
                FractionalEncoding, 'array'/'batch'/'matrix' for BatchEncoding

        """
        cdef ifstream* inputter
        cdef string bFileName = fileName.encode('utf8')
        inputter = new ifstream(bFileName,binary)
        try:
            self._ptr_ctxt.load(deref(inputter))
        finally:
            del inputter
        self._encoding = to_ENCODING_t(encoding).value

    cpdef void from_bytes(self, bytes content, encoding) except +:
        """from_bytes(bytes content)

        Recover the serialized ciphertext from a binary/bytes string.

        Args:
            content: (:obj:`bytes`) Python bytes object containing the PyCtxt.
            encoding: (:obj: `str`) String describing the encoding: 'int' for
                IntegerEncoding (default), 'float'/'fractional'/'double' for
                FractionalEncoding, 'array'/'batch'/'matrix' for BatchEncoding
        """
        cdef stringstream inputter
        inputter.write(content,len(content))
        self._ptr_ctxt.load(inputter)
        self._encoding = to_ENCODING_t(encoding).value

            
    # =========================================================================
    # ============================= OPERATIONS ================================
    # =========================================================================

            
    def __neg__(self):
        """Negates this ciphertext.
        """
        self._pyfhel.negate(self)
        
    def __add__(self, other):
        """Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result a new ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Second summand.

        Returns:
            (PyCtxt): Ciphertext resulting of substraction

        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            return self._pyfhel.add(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.add_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be either PyCtxt or PyPtxt")
    
    def __radd__(self, other): return self.__add__(other)
    def __iadd__(self, other):
        """Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Second summand.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.add(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            self._pyfhel.add_plain(self, other, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be either PyCtxt or PyPtxt")
            

    def __sub__(self, other):
        """Substracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Substracts with a PyPtxt/PyCtxt, storing the result in a new ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Substrahend, to be substracted from this ciphertext.
        Returns:
            (PyCtxt): Ciphertext resulting of substraction

        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            return self._pyfhel.sub(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.sub_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
    def __rsub__(self, other): return self.__sub__(other)
    def __isub__(self, other): 
        """Substracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Substracts with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Substrahend, to be substracted from this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.sub(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            self._pyfhel.sub_plain(self, other, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
    
                        
    def __mul__(self, other):
        """Multiplies this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Multiplies with a PyPtxt/PyCtxt, storing the result in a new ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Multiplier, to be multiplied with this ciphertext.

        Returns:
            (PyCtxt): Ciphertext resulting of multiplication

        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            return self._pyfhel.multiply(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.multiply_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt or PyPtxt"
                            "(is %s instead)"%(type(other)))
     
    def __rmul__(self, other): return self.__mul__(other)
    def __imul__(self, other): 
        """Multiplies this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Multiplies with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt|PyPtxt): Multiplier, to be multiplied with this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            return self._pyfhel.multiply(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.multiply_plain(self, other, in_new_ctxt=False)
        else:
             raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt or PyPtxt"
                            "(is %s instead)"%(type(other)))
           
                                    
    def __pow__(self, exponent, modulo):
        """Exponentiates this ciphertext to the desired exponent.
        
        Exponentiates to the desired exponent.

        Args:
            exponent (int): Exponent for the power.
        """
        if(exponent==2):
            self._pyfhel.square()  
        else:
            self._pyfhel.exponentiate(exponent)     
                
                
    def __rshift__(self, k):
        """Rotates this ciphertext k positions.

        Args:
            k (int): Number of positions to rotate.
        """
        self._pyfhel.rotate(self, k)


    # =========================================================================
    # ============================ ENCR/DECR/CMP ==============================
    # =========================================================================

    def __len__(self):
        return self.size()

    def __int__(self):
        if (self._encoding != ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> wrong PyCtxt encoding (not INTEGER)")
        return self._pyfhel.decryptInt(self)

    def __float__(self):
        if (self._encoding != ENCODING_T.FRACTIONAL):
            raise RuntimeError("<Pyfhel ERROR> wrong PyCtxt encoding (not FRACTIONAL)")
        return self._pyfhel.decryptFrac(self)
    
    def __str__(self):
        return "<Pyfhel Ciphertext, encoding={}, size={}>".format(
                ENCODING_t(self._encoding).name, self.size())

    



# -------------------------------- AUXILIARY ----------------------------------
cpdef to_ENCODING_t(encoding):
    """to_ENCODING_t(encoding)
    
    Turns `encoding` into a valid ENCODING_t type. 
    
    If `encoding` is str, 'int' for IntegerEncoding,
                          'float'/'fractional'/'double' for FractionalEncoding,
                          'array'/'batch'/'matrix' for BatchEncoding
    
    """
    if type(encoding) is unicode or isinstance(encoding, unicode):
        # encoding is a string. Casting it to str just in case.
        encoding = unicode(encoding)
        if encoding.lower()[0] == 'i':
            return ENCODING_t.INTEGER
        elif encoding.lower()[0] in 'fd':
            return ENCODING_t.FRACTIONAL
        elif encoding.lower()[0] in 'abm':
            return ENCODING_t.BATCH

    elif type(encoding) is type:
        if encoding is int:
            return ENCODING_t.INTEGER
        elif encoding is float:
            return ENCODING_t.FRACTIONAL
        if encoding is list:
            return ENCODING_t.BATCH
        
    elif isinstance(encoding, (int, float)) and\
         int(encoding) in (ENCODING_t.INTEGER.value,
                           ENCODING_t.FRACTIONAL.value,
                           ENCODING_t.BATCH.value):
            return ENCODING_t(int(encoding))
        
    else:
        raise TypeError("<Pyfhel ERROR>: encoding unknown. Could not convert to ENCODING_t.")
