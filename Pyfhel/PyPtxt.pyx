# distutils: language = c++
#cython: language_level=3, boundscheck=False

"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util import ENCODING_t

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyPtxt:
    """Plaintext of Pyfhel. Contains a value/vector of unencrypted ints/doubles.

    This class references SEAL, PALISADE and HElib plaintexts, using the one 
    corresponding to the backend selected in Pyfhel (SEAL by default).

    Attributes:
        other_ptxt (PyPtxt, optional): Other PyPtxt to deep copy
    
    """
    
    def __cinit__(self, 
                  PyPtxt copy_ptxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  encoding=None):
        if (copy_ptxt): # If there is a PyPtxt to copy, override all arguments and copy
            self._ptr_ptxt = new Plaintext(deref(copy_ptxt._ptr_ptxt))
            self._encoding = copy_ptxt._encoding
            if (copy_ptxt._pyfhel):
                self._pyfhel = copy_ptxt._pyfhel
        else:
            self._ptr_ptxt = new Plaintext()  
            if fileName:
                if not encoding:
                    raise TypeError("<Pyfhel ERROR> PyPtxt initialization with loading requires valid encoding")    
                self.from_file(fileName, encoding)
            else:
                self._encoding = to_ENCODING_t(encoding) if encoding else ENCODING_T.UNDEFINED
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
        
        
    cpdef bool is_zero(self) except +:
        """bool: Flag to quickly check if it is empty"""
        return self._ptr_ptxt.is_zero()
    
    cpdef string to_string(self) except +:
        """string: Polynomial representation of the plaintext"""
        return self._ptr_ptxt.to_string()
    
    
    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    cpdef void to_file(self, fileName) except +:
        """to_file(Path fileName)
        
        Alias of `save` with input sanitizing.
        """
        self.save(_to_valid_file_str(fileName))

    cpdef void save(self, str fileName) except +:
        """Save the plaintext into a file.

        Args:
            fileName: (:obj:`str`) File where the plaintext will be stored.

        """
        cdef ofstream* outputter
        cdef string bFileName = fileName.encode('utf8')
        outputter = new ofstream(bFileName, binary)
        try:
            self._ptr_ptxt.save(deref(outputter))
        finally:
            del outputter

    cpdef bytes to_bytes(self) except +:
        """to_bytes()

        Serialize the plaintext into a binary/bytes string.

        Return:
            * bytes: serialized plaintext
        """
        cdef ostringstream outputter
        self._ptr_ptxt.save(outputter)
        return outputter.str()

    cpdef void from_file(self, fileName, encoding) except +:
        """from_file(str fileName)
        
        Alias of `load` with input sanitizer.
        """
        self.load(_to_valid_file_str(fileName, check=True), encoding)

    cpdef void load(self, str fileName, encoding) except +:
        """load(self, str fileName)
        
        Load the plaintext from a file.

        Args:
            fileName: (:obj:`str`) File where the plaintext is retrieved from.
            encoding: (:obj: `str`) String or type describing the encoding:
                'int' or int for IntegerEncoding (default),
                'float'/'fractional'/'double' or float for FractionalEncoding,
                'array'/'batch'/'matrix' or list for BatchEncoding

        """
        cdef ifstream* inputter
        cdef string bFileName = fileName.encode('utf8')
        inputter = new ifstream(bFileName,binary)
        try:
            self._ptr_ptxt.load(deref(inputter))
        finally:
            del inputter
        self._encoding = to_ENCODING_t(encoding).value

    cpdef void from_bytes(self, bytes content, encoding) except +:
        """from_bytes(bytes content)

        Recover the serialized plaintext from a binary/bytes string.

        Args:
            content: (:obj:`bytes`) Python bytes object containing the PyPtxt.
            encoding: (:obj: `str`) String or type describing the encoding:
                'int' or int for IntegerEncoding (default),
                'float'/'fractional'/'double' or float for FractionalEncoding,
                'array'/'batch'/'matrix' or list for BatchEncoding
        """
        cdef stringstream inputter
        inputter.write(content,len(content))
        self._ptr_ptxt.load(inputter)
        self._encoding = to_ENCODING_t(encoding).value



    # =========================================================================
    # ============================ ENCR/DECR/CMP ==============================
    # =========================================================================

    def __int__(self):
        if (self._encoding != ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> wrong PyCtxt encoding (not INTEGER)")
        return self._pyfhel.decodeInt(self)

    def __float__(self):
        if (self._encoding != ENCODING_T.FRACTIONAL):
            raise RuntimeError("<Pyfhel ERROR> wrong PyCtxt encoding (not FRACTIONAL)")
        return self._pyfhel.decodeFrac(self)
    
    def __str__(self):
        return "<Pyfhel Ciphertext, encoding={}, size={}>".format(
                ENCODING_t(self._encoding).name, self.size())

    def encode(self, value):
        self._pyfhel.encode(value, self)
    
    def decode(self):
        self._pyfhel.decode(self)