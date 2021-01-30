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
    """Plaintext class of Pyfhel, contains a value/vector of encoded ints/double.

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
                
    def __init__(self,
                  PyPtxt copy_ptxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  encoding=None):
        """__init__(PyPtxt copy_ctxt=None, Pyfhel pyfhel=None, fileName=None, encoding=None)

        Initializes an empty PyPtxt encoded plaintext.
        
        To fill the ciphertext during initialization you can:
            - Provide a PyPtxt to deep copy. 
            - Provide a pyfhel instance to act as its backend.
            - Provide a fileName and an encoding to load the data from a saved file.

        Attributes:
            copy_ctxt (PyPtxt, optional): Other PyPtxt to deep copy.
            pyfhel (Pyfhel, optional): Pyfhel instance needed to operate.
            fileName (str, pathlib.Path, optional): Load PyPtxt from this file.
                            Requires non-empty encoding.
            encoding (str, type, int, optional): encoding type of the new PyPtxt.
        """
        pass

    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    @property
    def _encoding(self):
        """ENCODING_t: returns the encoding type.
        
        Can be set to: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH

        See Also:
            :func:`~Pyfhel.util.to_ENCODING_t`

        :meta public:
        """
        return ENCODING_t(self._encoding)
    
    @_encoding.setter
    def _encoding(self, new_encoding):
        if not isinstance(new_encoding, ENCODING_t):
            raise TypeError("<Pyfhel ERROR> Encoding type of PyPtxt must be ENCODING_t")        
        self._encoding = new_encoding.value
        
    @_encoding.deleter
    def _encoding(self):
        self._encoding = ENCODING_t.UNDEFINED.value
              
        
    @property
    def _pyfhel(self):
        """A pyfhel instance, used for operations"""
        return self._pyfhel

    @_pyfhel.setter
    def _pyfhel(self, new_pyfhel):
        if not isinstance(new_pyfhel, Pyfhel):
            raise TypeError("<Pyfhel ERROR> new_pyfhel needs to be a Pyfhel class object")       
        self._pyfhel = new_pyfhel 
        
        
    cpdef bool is_zero(self) except +:
        """bool: Flag to quickly check if it is empty"""
        return self._ptr_ptxt.is_zero()

    cpdef string to_poly_string(self) except +:
        """str: Polynomial representation of the plaintext"""
        return self._ptr_ptxt.to_string()
    
    
    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    cpdef void to_file(self, fileName) except +:
        """to_file(Path fileName)
        
        Alias of `save` with input sanitizing.

        Args:
            fileName: (str, pathlib.Path) File where the ciphertext will be stored.

        Return:
            None
        """
        self.save(_to_valid_file_str(fileName))

    cpdef void save(self, str fileName) except +:
        """save(str fileName)
        
        Save the plaintext into a file. The file can new one or
        exist already, in which case it will be overwriten.

        Args:
            fileName: (str) File where the plaintext will be stored.

        Return:
            None            
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
            bytes: serialized plaintext
        """
        cdef ostringstream outputter
        self._ptr_ptxt.save(outputter)
        return outputter.str()

    cpdef void from_file(self, fileName, encoding) except +:
        """from_file(str fileName, encoding)
        
        Alias of `load` with input sanitizer.

        Load the ciphertext from a file. Requires knowing the encoding.

        Args:
            fileName (str, pathlib.Path): path to file where the ciphertext is retrieved from.
            encoding: (str, type, int, ENCODING_t) One of the following:
              * ('int', 'integer', int, 1, ENCODING_t.INTEGER) -> integer encoding.
              * ('float', 'double', float, 2, ENCODING_t.FRACTIONAL) -> fractional encoding.
              * ('array', 'batch', 'matrix', list, 3, ENCODING_t.BATCH) -> batch encoding.

        Return:
            None

        See Also:
            :func:`~Pyfhel.util.to_ENCODING_t`
        """
        self.load(_to_valid_file_str(fileName, check=True), encoding)

    cpdef void load(self, str fileName, encoding) except +:
        """load(self, str fileName, encoding)
        
        Load the plaintext from a file.

        Args:
            fileName: (str) Valid file where the plaintext is retrieved from.
            encoding: (str, type, int, ENCODING_t) One of the following:
              * ('int', 'integer', int, 1, ENCODING_t.INTEGER) -> integer encoding.
              * ('float', 'double', float, 2, ENCODING_t.FRACTIONAL) -> fractional encoding.
              * ('array', 'batch', 'matrix', list, 3, ENCODING_t.BATCH) -> batch encoding.
              
        Return:
            None

        See Also:
            :func:`~Pyfhel.util.to_ENCODING_t`
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
              * ('int', 'integer', int, 1, ENCODING_t.INTEGER) -> integer encoding.
              * ('float', 'double', float, 2, ENCODING_t.FRACTIONAL) -> fractional encoding.
              * ('array', 'batch', 'matrix', list, 3, ENCODING_t.BATCH) -> batch encoding.
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
    
    def __repr__(self):
        return "<Pyfhel Plaintext, encoding={}, poly={}>".format(
                ENCODING_t(self._encoding).name,
                str(self.to_poly_string())[:25] + ('...' if len(str(self.to_poly_string()))>25 else ''))

    def encode(self, value):
        """encode(value)
        
        Encodes the given value using _pyfhel.
        
        Arguments:
            value (int, float, np.array): Encodes accordingly to the tipe
            
        Return:
            None
            
        See Also:
            :func:`~Pyfhel.Pyfhel.encode`
        """
        self._pyfhel.encode(value, self)
    
    def decode(self):
        """decode()
        
        Decodes itself using _pyfhel.
        
        Arguments:
            None
            
        Return:
            int, float, np.array: value decrypted.
   
        See Also:
            :func:`~Pyfhel.Pyfhel.decode`
        """
        self._pyfhel.decode(self)