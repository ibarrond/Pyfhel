"""PyPtxt. Plaintext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Used for all kinds of operations. Includes utility functions
from .Pyfhel import Pyfhel
from .utils import Scheme_t, Backend_t, _to_valid_file_str

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# Import Abstract Plaintext class
from Pyfhel.Afhel.Afhel cimport *

import numpy as np

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
                  bytestring=None,
                  scheme=None):
        if (copy_ptxt): # If there is a PyPtxt to copy, override all arguments and copy
            self._ptr_ptxt = new AfsealPtxt(deref(<AfsealPtxt*>copy_ptxt._ptr_ptxt))
            self._scheme = copy_ptxt._scheme
            if (copy_ptxt._pyfhel):
                self._pyfhel = copy_ptxt._pyfhel
        else:
            self._ptr_ptxt = new AfsealPtxt()
            if pyfhel:
                self._pyfhel = pyfhel
                self._scheme = self._pyfhel.afseal.get_scheme()
            elif scheme:
                self._scheme = (to_Scheme_t(scheme) if scheme else Scheme_t.none).value
            if fileName:
                if self._scheme == scheme_t.none:
                    raise TypeError("<Pyfhel ERROR> PyPtxt initialization with loading requires valid scheme")    
                self.load(fileName, to_Scheme_t(self._scheme))
            elif bytestring:
                if self._scheme == scheme_t.none:
                    raise TypeError("<Pyfhel ERROR> PyPtxt initialization from bytestring requires valid scheme")    
                self.from_bytes(bytestring, to_Scheme_t(self._scheme))
                
    def __init__(self,
                  PyPtxt copy_ptxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  bytestring=None,
                  scheme=None):
        """__init__(PyPtxt copy_ctxt=None, Pyfhel pyfhel=None, fileName=None, scheme=None)

        Initializes an empty PyPtxt encoded plaintext.
        
        To fill the plaintext during initialization you can:
            - Provide a PyPtxt to deep copy. 
            - Provide a pyfhel instance to act as its backend.
            - Provide a fileName and an scheme to load the data from a saved file.

        Attributes:
            copy_ctxt (PyPtxt, optional): Other PyPtxt to deep copy.
            pyfhel (Pyfhel, optional): Pyfhel instance needed to operate.
            fileName (str, pathlib.Path, optional): Load PyPtxt from this file.
                            Requires non-empty scheme.
            scheme (str, type, int, optional): scheme type of the new PyPtxt.
        """
        pass

    def __dealloc__(self):
        if self._ptr_ptxt != NULL:
            del self._ptr_ptxt
            
    @property
    def scheme(self):
        """scheme: returns the scheme type.
        
        Can be set to: 0-none, 1-bfv, 2-ckks, 3-bgv

        See Also:
            :func:`~Pyfhel.utils.to_Scheme_t`
        """
        return to_Scheme_t(self._scheme)
    @scheme.setter
    def scheme(self, new_scheme):
        new_scheme = to_Scheme_t(new_scheme)    
        self._scheme = new_scheme.value
    @scheme.deleter
    def scheme(self):
        self._scheme = scheme_t.none

    @property
    def scale(self):
        """double: multiplying factor to encode values in ckks."""
        return (<AfsealPtxt*>(self._ptr_ptxt)).scale()
    @scale.setter
    def scale(self, new_scale):
        self.set_scale(new_scale)

    @property
    def scale_bits(self):
        """int: number of bits in scale to encode values in ckks"""
        return <int>np.log2( (<AfsealPtxt*>(self._ptr_ptxt)).scale() )
        
    @property
    def _pyfhel(self):
        """A pyfhel instance, used for operations"""
        return self._pyfhel
    @_pyfhel.setter
    def _pyfhel(self, new_pyfhel):
        if not isinstance(new_pyfhel, Pyfhel):
            raise TypeError("<Pyfhel ERROR> new_pyfhel needs to be a Pyfhel class object")       
        self._pyfhel = new_pyfhel

    @property
    def mod_level(self):
        """mod_level: returns the number of moduli consumed so far.
        
        Only usable in ckks.
        """
        return self._mod_level
    @mod_level.setter
    def mod_level(self, newlevel):  
        self._mod_level = newlevel
    @mod_level.deleter
    def mod_level(self):
        self._mod_level = 0

    cpdef bool is_zero(self):
        """bool: Flag to quickly check if it is empty"""
        return (<AfsealPtxt*>self._ptr_ptxt).is_zero()

    cpdef string to_poly_string(self):
        """str: Polynomial representation of the plaintext"""
        return (<AfsealPtxt*>self._ptr_ptxt).to_string()
    
    cpdef bool is_ntt_form(self):
        """bool: Flag to quickly check if it is in NTT form"""
        return (<AfsealPtxt*>self._ptr_ptxt).is_ntt_form()
    
    
    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    cpdef void save(self, str fileName, str compr_mode="zstd"):
        """save(str fileName)
        
        Save the plaintext into a file. The file can new one or
        exist already, in which case it will be overwriten.

        Args:
            fileName: (str) File where the plaintext will be stored.
            compr_mode: (str) Compression mode. One of "none", "zlib", "zstd".

        Return:
            None            
        """
        if self._pyfhel is None:
            raise ValueError("<Pyfhel ERROR> plaintext saving requires a Pyfhel instance")
        cdef ofstream* outputter
        cdef string bFileName = _to_valid_file_str(fileName).encode('utf8')
        cdef string bcompr_mode = compr_mode.encode('utf8')
        outputter = new ofstream(bFileName, binary)
        try:
            self._pyfhel.afseal.save_plaintext(deref(outputter), bcompr_mode, deref(self._ptr_ptxt))
        finally:
            del outputter

    cpdef bytes to_bytes(self, str compr_mode="none"):
        """to_bytes()

        Serialize the plaintext into a binary/bytes string.

        Args:
            compr_mode: (str) Compression mode. One of "none", "zlib", "zstd"

        Return:
            bytes: serialized plaintext
        """
        if self._pyfhel is None:
            raise ValueError("<Pyfhel ERROR> plaintext serialization requires a Pyfhel instance")
        cdef ostringstream outputter
        cdef string bcompr_mode = compr_mode.encode('utf8')
        self._pyfhel.afseal.save_plaintext(outputter, bcompr_mode, deref(self._ptr_ptxt))
        return outputter.str()

    cpdef void load(self, str fileName, object scheme=None):
        """load(self, str fileName, scheme)
        
        Load the plaintext from a file.

        Args:
            fileName: (str) Valid file where the plaintext is retrieved from.
              
        Return:
            None

        See Also:
            :func:`~Pyfhel.utils.to_Scheme_t`
        """
        if self._pyfhel is None:
            raise ValueError("<Pyfhel ERROR> plaintext loading requires a Pyfhel instance")
        cdef ifstream* inputter
        cdef string bFileName = _to_valid_file_str(fileName, check=True).encode('utf8')
        inputter = new ifstream(bFileName, binary)
        try:
            self._pyfhel.afseal.load_plaintext(deref(inputter), deref(self._ptr_ptxt))
        finally:
            del inputter
        if scheme is not None:
            self.scheme = to_Scheme_t(scheme)

    cpdef void from_bytes(self, bytes content, object scheme=None):
        """from_bytes(bytes content)

        Recover the serialized plaintext from a binary/bytes string.

        Args:
            content: (:obj:`bytes`) Python bytes object containing the PyPtxt.
            scheme: (:obj: `str`) String or type describing the scheme:
              * ('int', 'integer', int, 1, scheme_t.bfv) -> integer scheme.
              * ('float', 'double', float, 2, scheme_t.ckks) -> fractional scheme.
              * (3, scheme_t.bgv) -> integer scheme.
        """
        if self._pyfhel is None:
            raise ValueError("<Pyfhel ERROR> plaintext loading requires a Pyfhel instance")
        cdef stringstream inputter
        inputter.write(content,len(content))
        self._pyfhel.afseal.load_plaintext(inputter, deref(self._ptr_ptxt))
        if scheme is not None:
            self.scheme = to_Scheme_t(scheme)



    # =========================================================================
    # ============================ ENCR/DECR/CMP ==============================
    # =========================================================================

    def __int__(self):
        """returns the integer in the first slot of the plaintext"""
        if (self._scheme != scheme_t.bfv and self._scheme != scheme_t.bgv):
            raise RuntimeError("<Pyfhel ERROR> wrong PyPtxt scheme for automatic encoding (not bfv/bfv)")
        return int(np.array(self._pyfhel.decodeInt(self))[0])

    def __float__(self):
        """returns the float in the first slot of the plaintext"""
        if (self._scheme != scheme_t.ckks):
            raise RuntimeError("<Pyfhel ERROR> wrong PyPtxt scheme for automatic encoding (not ckks)")
        return float(np.array(self._pyfhel.decodeFrac(self))[0])

    def __repr__(self):
        if self.is_ntt_form():
            poly_s = "?"
        else:
            poly_s = str(self.to_poly_string())
            poly_s = poly_s[:25] + ('...' if len(poly_s)>25 else '')
        return "<Pyfhel Plaintext at {}, scheme={}, poly={}, is_ntt={}{}>".format(
                hex(id(self)),
                self.scheme.name,
                poly_s,
                "Y" if self.is_ntt_form() else "-",
                ", mod_level={}".format(self.mod_level) if self.scheme==Scheme_t.ckks else ''
                )

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
        return self._pyfhel.encode(val_vec=value, ptxt=self)
    
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
        return self._pyfhel.decode(self)    
        
    cpdef void set_scale (self, double new_scale):
        """set_scale(double new_scale)

        Sets the scale of the ciphertext.
        
        Args:
            scale (double): new scale of the ciphertext.
        """
        (<AfsealPtxt*>(self._ptr_ptxt)).set_scale(new_scale)