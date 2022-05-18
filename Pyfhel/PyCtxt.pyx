# distutils: language = c++
# cython: language_level=3, boundscheck=False
"""PyCtxt. Ciphertext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import Pyfhel and PyPtxt for operations
from .Pyfhel import Pyfhel
from .PyPtxt import PyPtxt
from .utils.Scheme_t import Scheme_t
from .utils.Backend_t import Backend_t

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

import numpy as np
from typing import Union, Tuple
from warnings import warn

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyCtxt:
    """Ciphertext class of Pyfhel, contains a value/vector of encrypted ints/doubles.

    This class references SEAL and PALISADE ciphertexts, using the one 
    corresponding to the backend selected in Pyfhel. By default, it is SEAL.   
    """
    def __cinit__(self,
                  PyCtxt copy_ctxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  bytestring=None,
                  scheme=None):
        self._mod_level = 0
        if copy_ctxt: # If there is a PyCtxt to copy, override other args
            self._ptr_ctxt = new AfsealCtxt(deref(<AfsealCtxt*>copy_ctxt._ptr_ctxt))
            self._mod_level = copy_ctxt._mod_level
            self._scheme = copy_ctxt._scheme
            if (copy_ctxt._pyfhel):
                self._pyfhel = copy_ctxt._pyfhel
        
        else:
            self._ptr_ctxt = new AfsealCtxt()
            if pyfhel:
                self._pyfhel = pyfhel
                self._scheme = self._pyfhel.afseal.get_scheme()
            elif scheme:
                self._scheme = (to_Scheme_t(scheme) if scheme else Scheme_t.none).value
            if fileName:
                if self._scheme is scheme_t.none:
                    raise TypeError("<Pyfhel ERROR> PyCtxt initialization with fileName requires valid scheme")    
                self.load(fileName, to_Scheme_t(self._scheme))
            elif bytestring:
                if self._scheme is scheme_t.none:
                    raise TypeError("<Pyfhel ERROR> PyCtxt initialization from bytestring requires valid scheme")    
                self.from_bytes(bytestring, to_Scheme_t(self._scheme))
            
    def __dealloc__(self):
        if self._ptr_ctxt != NULL:
            del self._ptr_ctxt
    
    def __init__(self,
                  PyCtxt copy_ctxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  bytestring=None,
                  scheme=None):
        """__init__(PyCtxt copy_ctxt=None, Pyfhel pyfhel=None, fileName=None, bytestring=None, scheme=None)

        Initializes an empty PyCtxt ciphertext.
        
        To fill the ciphertext during initialization you can:
            - Provide a PyCtxt to deep copy. 
            - Provide a pyfhel instance to act as its backend.
            - Provide a fileName and an scheme to load the data from a saved file.

        Attributes:
            copy_ctxt (PyCtxt, optional): Other PyCtxt to deep copy.
            pyfhel (Pyfhel, optional): Pyfhel instance needed to operate.
            fileName (str, pathlib.Path, optional): Load PyCtxt from this file.
                            Requires non-empty scheme.
            bytestring (bytes, optional): Read PyCtxt from a bytes bytestring string, 
                            obtained by calling the to_bytes method.
            scheme (str, type, int, optional): scheme type of the new PyCtxt.
        """
        pass

    @property
    def scheme(self):
        """scheme: returns the scheme type.
        
        Can be set to: none, bfv (INTEGER) or ckks (FRACTIONAL).

        See Also:
            :func:`~Pyfhel.utils.to_Scheme_t`

        :meta public:
        """
        return Scheme_t(self._scheme)
    @scheme.setter
    def scheme(self, newscheme):
        new_scheme = to_Scheme_t(newscheme)
        if not isinstance(newscheme, Scheme_t):
            raise TypeError("<Pyfhel ERROR> scheme type of PyCtxt must be Scheme_t")        
        self._scheme = new_scheme.value
    @scheme.deleter
    def scheme(self):
        self._scheme = scheme_t.none

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

    @property
    def _pyfhel(self):
        """A Pyfhel instance, used for operations"""
        return self._pyfhel
    @_pyfhel.setter
    def _pyfhel(self, new_pyfhel):
        if not isinstance(new_pyfhel, Pyfhel):
            raise TypeError("<Pyfhel ERROR> new_pyfhel needs to be a Pyfhel class object")       
        self._pyfhel = new_pyfhel 
     
    cpdef int size(self):
        """Current size of the ciphertext.
        
        Return:
            int: size of this ciphertext"""
        return (<AfsealCtxt*>(self._ptr_ctxt)).size()

    @property    
    def capacity(self):
        """int: Maximum size the ciphertext can hold."""
        return (<AfsealCtxt*>(self._ptr_ctxt)).size_capacity()

    @property
    def size(self):
        """int: Actual size of the ciphertext."""
        return (<AfsealCtxt*>(self._ptr_ctxt)).size()

    @property
    def scale(self):
        """double: multiplying factor to encode values in ckks."""
        return (<AfsealCtxt*>(self._ptr_ctxt)).scale()
    @scale.setter
    def scale(self, new_scale):
        self.set_scale(new_scale)

    @property
    def scale_bits(self):
        """int: number of bits in scale to encode values in ckks"""
        return <int>np.log2( (<AfsealCtxt*>(self._ptr_ctxt)).scale() )

    @property
    def noiseBudget(self):
        """int: Noise budget.
        
        A value of 0 means that it cannot be decrypted correctly anymore.
        
        See Also:
            :func:`~Pyfhel.Pyfhel.noiseLevel`
        """
        sk_not_empty = self._pyfhel is not None and not self._pyfhel.is_secret_key_empty()
        return self._pyfhel.noise_level(self) if sk_not_empty and (self.scheme == Scheme_t.bfv) else -1

    cpdef void set_scale (self, double new_scale):
        """set_scale(double new_scale)

        Sets the scale of the ciphertext.
        
        Args:
            scale (double): new scale of the ciphertext.
        """
        (<AfsealCtxt*>(self._ptr_ctxt)).set_scale(new_scale)

    cpdef void round_scale(self):
        """round_scale()

        Rounds the scale of the ciphertext to the nearest power of 2.
        """
        self.set_scale( pow(2, <int>np.round(np.log2( (<AfsealCtxt*>(self._ptr_ctxt)).scale() ))) )

    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    def __reduce__(self):
        """__reduce__()

        Required for pickling purposes. Returns a tuple with:
            - A callable object that will be called to create the initial version of the object.
            - A tuple of arguments for the callable object.
        """
        return (PyCtxt, (None, None, None, self.to_bytes(), self.scheme))

    cpdef void save(self, str fileName, str compr_mode="zstd"):
        """save(str fileName)
        
        Save the ciphertext into a file. The file can new one or
        exist already, in which case it will be overwriten.

        Args:
            fileName: (str) File where the ciphertext will be stored.
            compr_mode: (str) Compression mode. One of "none", "zlib", "zstd".

        Return:
            None            
        """
        cdef ofstream* outputter
        cdef string bFileName = _to_valid_file_str(fileName).encode('utf8')
        cdef string bcompr_mode = compr_mode.lower().encode('utf8')
        outputter = new ofstream(bFileName, binary)
        try:
            self._pyfhel.afseal.save_ciphertext(deref(outputter), bcompr_mode, deref(self._ptr_ctxt))
        finally:
            del outputter

    cpdef bytes to_bytes(self, str compr_mode="none"):
        """to_bytes()

        Serialize the ciphertext into a binary/bytes string.

        Args:
            compr_mode: (str) Compression mode. One of "none", "zlib", "zstd".

        Return:
            bytes: serialized ciphertext
        """
        cdef ostringstream outputter
        cdef string bcompr_mode = compr_mode.encode('utf8')
        self._pyfhel.afseal.save_ciphertext(outputter, bcompr_mode, deref(self._ptr_ctxt))
        return outputter.str()

    cpdef void load(self, str fileName, object scheme):
        """load(self, str fileName, scheme)
        
        Load the ciphertext from a file.

        Args:
            fileName: (str) Valid file where the ciphertext is retrieved from.
            scheme (str, type, int, Scheme_t): One of the following:

                * ('int', 'INTEGER', int, 1, Scheme_t.bfv) -> integer scheme.
                * ('float', 'FRACTIONAL', float, 2, Scheme_t.ckks) -> fractional scheme.

              
        Return:
            None

        See Also:
            :func:`~Pyfhel.utils.to_Scheme_t`
        """
        cdef ifstream* inputter
        cdef string bFileName = _to_valid_file_str(fileName, check=True).encode('utf8')
        inputter = new ifstream(bFileName, binary)
        try:
            self._pyfhel.afseal.load_ciphertext(deref(inputter), deref(self._ptr_ctxt))
        finally:
            del inputter
        self.scheme = to_Scheme_t(scheme)

    cpdef void from_bytes(self, bytes content, object scheme):
        """from_bytes(bytes content, scheme)

        Recover the serialized ciphertext from a binary/bytes string.

        Args:
            content (bytes):  Python bytes object containing the PyCtxt.
            scheme (str, type, int, Scheme_t): One of the following:

                * ('int', 'INTEGER', int, 1, Scheme_t.bfv) -> integer scheme.
                * ('float', 'FRACTIONAL', float, 2, Scheme_t.ckks) -> fractional scheme.

        Return:
            None

        See Also:
            :func:`~Pyfhel.utils.to_Scheme_t`
        """
        cdef stringstream inputter
        inputter.write(content,len(content))
        self._pyfhel.afseal.load_ciphertext(inputter, deref(self._ptr_ctxt))
        self.scheme = to_Scheme_t(scheme)

            
    # =========================================================================
    # ============================= OPERATIONS ================================
    # =========================================================================          
    def __neg__(self):
        """__neg__()
        
        Negates this ciphertext.
        """
        self._pyfhel.negate(self, in_new_ctxt=True)
        return self
        
    def __add__(self, other):
        """__add__(other)
        
        Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result a new ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Second summand.

        Returns:
            PyCtxt: Ciphertext resulting of addition.

        Raise:
            TypeError: if other doesn't have a valid type.

        See Also:
            :func:`~Pyfhel.Pyfhel.add`
        """
        other_ = self.encode_operand(other)
        self_, other_ = self._pyfhel.align_mod_n_scale(self, other_, 
                                    copy_other=(other_ is other))
        if isinstance(other_, PyCtxt):
            return self_._pyfhel.add(self_, other_, in_new_ctxt=True)
        elif isinstance(other_, PyPtxt):
            return self_._pyfhel.add_plain(self_, other_, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be numeric, array, PyCtxt or PyPtxt")
    
    def __radd__(self, other): return self.__add__(other)
    def __iadd__(self, other):
        """Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Second summand.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        other_ = self.encode_operand(other)
        _, other_ = self._pyfhel.align_mod_n_scale(self, other_,
                                copy_this=False, copy_other=(other_ is other))
        if isinstance(other_, PyCtxt):
            self._pyfhel.add(self, other_, in_new_ctxt=False)
        elif isinstance(other_, PyPtxt):
            self._pyfhel.add_plain(self, other_, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be numeric, array, PyCtxt or PyPtxt")
        return self


    def __sub__(self, other):
        """__sub__(other)
        
        Subtracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Subtracts with a PyPtxt/PyCtxt, storing the result in a new ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Substrahend, to be subtracted from this ciphertext.
        Returns:
            PyCtxt: Ciphertext resulting of subtraction

        Raise:
            TypeError: if other doesn't have a valid type.
            
        See Also:
            :func:`~Pyfhel.Pyfhel.sub`
        """
        other_ = self.encode_operand(other)
        self_, other_ = self._pyfhel.align_mod_n_scale(self, other_, 
                                    copy_other=(other_ is other))
        if isinstance(other_, PyCtxt):
            return self_._pyfhel.sub(self_, other_, in_new_ctxt=True)
        elif isinstance(other_, PyPtxt):
            return self_._pyfhel.sub_plain(self_, other_, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be numeric, array, PyCtxt or PyPtxt")
    
    def __rsub__(self, other): return self.__sub__(other)
    def __isub__(self, other): 
        """Subtracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Subtracts with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Substrahend, to be subtracted from this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        other_ = self.encode_operand(other)
        _, other_ = self._pyfhel.align_mod_n_scale(self, other_,
                                copy_this=False, copy_other=(other_ is other))
        if isinstance(other_, PyCtxt):
            self._pyfhel.sub(self, other_, in_new_ctxt=False)
        elif isinstance(other_, PyPtxt):
            self._pyfhel.sub_plain(self, other_, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be numeric, array, PyCtxt or PyPtxt")
        return self
                        
    def __mul__(self, other):
        """__mul__(other)
        
        Multiplies this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Multiplies with a PyPtxt/PyCtxt, storing the result in a new ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Multiplier, to be multiplied with this ciphertext.

        Returns:
            PyCtxt: Ciphertext resulting of multiplication

        Raise:
            TypeError: if other doesn't have a valid type.
            
        See Also:
            :func:`~Pyfhel.Pyfhel.multiply`
        """
        other = self.encode_operand(other)
        if isinstance(other, PyCtxt):
            return self._pyfhel.multiply(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.multiply_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt, PyPtxt or numerical"
                            "(is %s instead)"%(type(other)))
     
    def __rmul__(self, other): return self.__mul__(other)
    def __imul__(self, other): 
        """Multiplies this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Multiplies with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Multiplier, to be multiplied with this ciphertext.

        Returns:
            PyCtxt: Ciphertext resulting of multiplication

        Raise:
            TypeError: if other doesn't have a valid type.
        """
        other = self.encode_operand(other)
        if isinstance(other, PyCtxt):
            self._pyfhel.multiply(self, other, in_new_ctxt=False)
            return self
        elif isinstance(other, PyPtxt):
            self._pyfhel.multiply_plain(self, other, in_new_ctxt=False)
            return self
        raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt,"
                        " PyPtxt, int|float or 1D np.array"
                        "(is %s instead)"%(type(other)))


    def __truediv__(self, divisor):
        """__truediv__(divisor)
        
        Multiplies this ciphertext with the inverse of divisor.
        
        This operation can only be done with plaintexts. Division between two Ciphertexts is not possible.

        For bfv Integer Scheme, the inverse is calculated as:
            inverse -> (divisor * inverse) mod p = 1

        For ckks Fractional scheme, the inverse is calculated as 1/divisor.

        Args:
            divisor (int, float, PyPtxt): divisor for the operation.
        """
        if isinstance(divisor, PyPtxt):
            divisor = divisor.decode()
        if not isinstance(divisor, (int, float)):
            raise TypeError("<Pyfhel ERROR> divisor must be float, int"
                            "or PyPtxt with bfv/ckks scheme (is %s:%s instead)"
                            %(str(divisor),type(divisor)))
        # Compute inverse. Int: https://stackoverflow.com/questions/4798654
        if self.scheme == Scheme_t.bfv:
            divisor = np.int64(divisor)
            p = self._pyfhel.getp()
            inverse = pow(divisor, p-2, p)
            inversePtxt = self.encode_operand(inverse)
        elif self.scheme == Scheme_t.ckks: # float. Standard inverse
            inverse = 1/np.float64(divisor)
            inversePtxt = self.encode_operand(inverse)
        else:
            raise TypeError("<Pyfhel ERROR> dividend scheme doesn't support"
                            "division (%s)"%(self.scheme))
        self_, _ = self._pyfhel.align_mod_n_scale(self, inversePtxt,
                                          copy_this=True, copy_other=False)
        return self_._pyfhel.multiply_plain(self_, inversePtxt, in_new_ctxt=False)

    def __itruediv__(self, divisor):
        """Multiplies this ciphertext with the inverse of divisor.
        
        This operation can only be done with plaintexts. Division between 
        two Ciphertexts is not possible.

        For bfv Integer Scheme, the inverse is calculated as:
            inverse -> (divisor * inverse) mod p = 1

        For ckks Fractional scheme, the inverse is calculated as 1/divisor.

        Args:
            divisor (int, float, PyPtxt): divisor for the operation.
        """
        if isinstance(divisor, PyPtxt):
            divisor = divisor.decode()
        if not isinstance(divisor, (int, float)):
            raise TypeError("<Pyfhel ERROR> divisor must be float, int"
                            "or PyPtxt with bfv/ckks scheme (is %s:%s instead)"
                            %(str(divisor),type(divisor)))
        # Compute inverse. Int: https://stackoverflow.com/questions/4798654
        if self.scheme == Scheme_t.bfv:
            divisor = np.int64(divisor)
            p = self._pyfhel.getp()
            inverse = pow(divisor, p-2, p)
            inversePtxt = self.encode_operand(inverse)
        elif self.scheme == Scheme_t.ckks: # float. Standard inverse
            inverse = 1/np.float64(divisor)
            inversePtxt = self.encode_operand(inverse)
        else:
            raise TypeError("<Pyfhel ERROR> dividend scheme doesn't support"
                            "division (%s)"%(self.scheme))
        self_, _ = self._pyfhel.align_mod_n_scale(self, inversePtxt,
                                          copy_this=False, copy_other=False)
        return self_._pyfhel.multiply_plain(self_, inversePtxt, in_new_ctxt=False)

                                    
    def __pow__(self, exponent, modulo):
        """__pow__(exponent)
        
        Exponentiates this ciphertext to the desired exponent.
        
        Exponentiates to the desired exponent.

        Args:
            exponent (int): Exponent for the power.
            
        See Also:
            :func:`~Pyfhel.Pyfhel.power`
        """
        if(exponent==2):
            return self._pyfhel.square(self, in_new_ctxt=True)  
        else:
            return self._pyfhel.power(self, expon=exponent, in_new_ctxt=True)

    def __ipow__(self, exponent):
        """Exponentiates this ciphertext to the desired exponent, inplace.
        
        Exponentiates to the desired exponent.

        Args:
            exponent (int): Exponent for the power.
        """
        if(exponent==2):
            self._pyfhel.square(self, in_new_ctxt=False)  
        else:
            self._pyfhel.power(self, expon=exponent, in_new_ctxt=False)
        return self
                
    def __rshift__(self, k):
        """__rshift__(k)
        
        Rotates this ciphertext k positions to the right.
        
        Args:
            k (int): Number of positions to rotate.
        """
        return self._pyfhel.rotate(self, -k, in_new_ctxt=True)

    def __irshift__(self, k):
        """Rotates this ciphertext k positions to the right, in-place.

        Args:
            k (int): Number of positions to rotate.
        """
        self._pyfhel.rotate(self, -k, in_new_ctxt=False)
        return self

    def __lshift__(self, k):
        """Rotates this ciphertext k positions to the left.

        Args:
            k (int): Number of positions to rotate.
        """
        return self._pyfhel.rotate(self, k, in_new_ctxt=True)

    def __ilshift__(self, k):
        """Rotates this ciphertext k positions to the left, in-place.

        Args:
            k (int): Number of positions to rotate.
        """
        self._pyfhel.rotate(self, k, in_new_ctxt=False)
        return self

    def __invert__(self):
        """__invert__()
        
        Relinarizes this ciphertext in-place.

        Requires valid relinearization keys.

        See Also:
            :func:`~Pyfhel.Pyfhel.relinearize`
        """
        self._pyfhel.relinearize(self)
        return self

    # =========================================================================
    # ============================ ENCR/DECR/CMP ==============================
    # =========================================================================

    def __len__(self):
        """__len__()
        
        Return the current size of the ciphertext.
        
        See Also:
            :func:`~Pyfhel.PyCtxt.size`
        """
        return (<AfsealCtxt*>(self._ptr_ctxt)).size()
    
    def __repr__(self):
        """__repr__()
        
        Prints information about the current ciphertext"""
        if self.scheme==Scheme_t.bfv:
            scheme_dep_info = 'noiseBudget=' + str(self.noiseBudget) \
                                            if self.noiseBudget!=-1 else "?"
        elif self.scheme==Scheme_t.ckks:
            scheme_dep_info = 'scale_bits=' + str(self.scale_bits) + \
                            ', mod_level=' + str(self.mod_level)
        else:
            scheme_dep_info = "?"
        return "<Pyfhel Ciphertext at {}, scheme={}, size={}/{}, {}>".format(
                hex(id(self)),
                self.scheme.name,
                self.size(),
                self.capacity,
                scheme_dep_info
                )
                
    def __bytes__(self):
        """__bytes__()
        
        Serialize current ciphertext to bytes"""
        return self.to_bytes(compr_mode="none")

    def encrypt(self, value):
        """encrypt(value)
        
        Encrypts the given value using _pyfhel.
        
        Arguments:
            value (int, float, np.array): Encrypts accordingly to the tipe
            
        Return:
            None
            
        See Also:
            :func:`~Pyfhel.Pyfhel.encrypt`
        """
        self._pyfhel.encrypt(ptxt=value, ctxt=self, scale=self.scale)
    
    def decrypt(self):
        """decrypt()
        
        Decrypts itself using _pyfhel.
        
        Arguments:
            None
            
        Return:
            int, float, np.array: value decrypted.
   
        See Also:
            :func:`~Pyfhel.Pyfhel.decrypt`
        """
        return self._pyfhel.decrypt(self, decode=True)

    def encode_operand(self, other):
        """encode_operand(other)
        
        Encodes the given value into a PyPtxt using _pyfhel.
        
        Arguments:
            other (int, float, np.array, list): Encodes accordingly to the type
            
        Return:
            PyPtxt: Encoded value

        See Also:
            :func:`~Pyfhel.Pyfhel.encode`
        """
        if isinstance(other, (int, float, list, np.ndarray)):
            other = np.array(other)
            if (other.ndim==0):     # nSlots = n in bfv, nSlots = n//2 in ckks
                other = np.repeat(other, self._pyfhel.n // (1 + (self.scheme==Scheme_t.ckks)))
            if (other.ndim==1) and \
                (np.issubdtype(other.dtype, np.number)):
                if self.scheme == Scheme_t.bfv:
                    return self._pyfhel.encodeInt(other.astype(np.int64))
                elif self.scheme == Scheme_t.ckks:
                    if np.issubdtype(other.dtype, np.complexfloating):
                        return self._pyfhel.encodeComplex(other.astype(complex), ptxt=None)
                    else:
                        return self._pyfhel.encodeFrac(other.astype(np.float64), ptxt=None)
        else:
            return other
