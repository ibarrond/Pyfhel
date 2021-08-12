# distutils: language = c++
# cython: language_level=3, boundscheck=False
"""PyCtxt. Ciphertext of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Import Pyfhel and PyPtxt for operations
from .Pyfhel import Pyfhel
from .PyPtxt import PyPtxt

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

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
                  serialized=None,
                  scheme=None):
        if (copy_ctxt): # If there is a PyCtxt to copy, override all arguments and copy
            self._ptr_ctxt = new Ciphertext(deref(copy_ctxt._ptr_ctxt))
            self._scheme = copy_ctxt._scheme
            if (copy_ctxt._pyfhel):
                self._pyfhel = copy_ctxt._pyfhel
        
        else:
            self._ptr_ctxt = new Ciphertext()
            if fileName:
                if not scheme:
                    raise TypeError("<Pyfhel ERROR> PyCtxt initialization with fileName requires valid scheme")    
                self.from_file(fileName, scheme)
            elif serialized:
                if not scheme:
                    raise TypeError("<Pyfhel ERROR> PyCtxt initialization from serialized requires valid scheme")    
                self.from_bytes(serialized, scheme)
            else:
                self._scheme = to_SCHEME_t(scheme) if scheme else SCHEME_t.UNDEFINED
            if (pyfhel):
                self._pyfhel = pyfhel
            
    def __dealloc__(self):
        if self._ptr_ctxt != NULL:
            del self._ptr_ctxt
    
    def __init__(self,
                  PyCtxt copy_ctxt=None,
                  Pyfhel pyfhel=None,
                  fileName=None,
                  serialized=None,
                  scheme=None):
        """__init__(PyCtxt copy_ctxt=None, Pyfhel pyfhel=None, fileName=None, serialized=None, scheme=None)

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
            serialized (bytes, optional): Read PyCtxt from a bytes serialized string, 
                            obtained by calling the to_bytes method.
            scheme (str, type, int, optional): scheme type of the new PyCtxt.
        """
        pass

    @property
    def _scheme(self):
        """SCHEME_t: returns the scheme type.
        
        Can be set to: UNDEFINED, BFV (INTEGER) or CKKS (FRACTIONAL).

        See Also:
            :func:`~Pyfhel.util.to_SCHEME_t`

        :meta public:
        """
        return SCHEME_t(self._scheme)
    
    @_scheme.setter
    def _scheme(self, new_scheme):
        new_scheme = to_SCHEME_t(new_scheme)
        if not isinstance(new_scheme, SCHEME_t):
            raise TypeError("<Pyfhel ERROR> scheme type of PyCtxt must be SCHEME_t")        
        self._scheme = new_scheme
        
    @_scheme.deleter
    def _scheme(self):
        self._scheme = SCHEME_t.UNDEFINED
        
    @property
    def _pyfhel(self):
        """A Pyfhel instance, used for operations"""
        return self._pyfhel
    @_pyfhel.setter
    def _pyfhel(self, new_pyfhel):
        if not isinstance(new_pyfhel, Pyfhel):
            raise TypeError("<Pyfhel ERROR> new_pyfhel needs to be a Pyfhel class object")       
        self._pyfhel = new_pyfhel 
        
    cpdef int size_capacity(self):
        """Maximum size the ciphertext can hold.
        
        Return:
            int: allocated size for this ciphertext
        """
        return self._ptr_ctxt.size_capacity()
     
    cpdef int size(self):
        """Current size of the ciphertext.
        
        Return:
            int: size of this ciphertext"""
        return self._ptr_ctxt.size()

    @property    
    def capacity(self):
        """int: Maximum size the ciphertext can hold."""
        return self._ptr_ctxt.size_capacity()

    @property
    def size(self):
        """int: Actual size of the ciphertext."""
        return self._ptr_ctxt.size()

    @property
    def noiseBudget(self):
        """int: Noise budget.
        
        A value of 0 means that it cannot be decrypted correctly anymore.
        
        See Also:
            :func:`~Pyfhel.Pyfhel.noiseLevel`
        """
        return self._pyfhel.noise_level(self)

    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    def __reduce__(self):
        """__reduce__()

        Required for pickling purposes. Returns a tuple with:
            - A callable object that will be called to create the initial version of the object.
            - A tuple of arguments for the callable object.
        """
        return (PyCtxt, (None, None, None, self.to_bytes(), self._scheme))

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
            scheme (str, type, int, SCHEME_t): One of the following:

                * ('int', 'INTEGER', int, 1, SCHEME_t.BFV) -> integer scheme.
                * ('float', 'FRACTIONAL', float, 2, SCHEME_t.CKKS) -> fractional scheme.

              
        Return:
            None

        See Also:
            :func:`~Pyfhel.util.to_SCHEME_t`
        """
        cdef ifstream* inputter
        cdef string bFileName = _to_valid_file_str(fileName, check=True).encode('utf8')
        inputter = new ifstream(bFileName, binary)
        try:
            self._pyfhel.afseal.load_ciphertext(deref(inputter), deref(self._ptr_ctxt))
        finally:
            del inputter
        self._scheme = to_SCHEME_t(scheme)

    cpdef void from_bytes(self, bytes content, object scheme):
        """from_bytes(bytes content, scheme)

        Recover the serialized ciphertext from a binary/bytes string.

        Args:
            content (bytes):  Python bytes object containing the PyCtxt.
            scheme (str, type, int, SCHEME_t): One of the following:

                * ('int', 'INTEGER', int, 1, SCHEME_t.BFV) -> integer scheme.
                * ('float', 'FRACTIONAL', float, 2, SCHEME_t.CKKS) -> fractional scheme.

        Return:
            None

        See Also:
            :func:`~Pyfhel.util.to_SCHEME_t`
        """
        cdef stringstream inputter
        inputter.write(content,len(content))
        self._pyfhel.afseal.load_ciphertext(inputter, deref(self._ptr_ctxt))
        self._scheme = to_SCHEME_t(scheme)

            
    # =========================================================================
    # ============================= OPERATIONS ================================
    # =========================================================================          
    def __neg__(self):
        """__neg__()
        
        Negates this ciphertext.
        """
        self._pyfhel.negate(self)
        
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
        if isinstance(other, PyCtxt):
            return self._pyfhel.add(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.add_plain(self, other, in_new_ctxt=True)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                return self._pyfhel.add_plain(self, other, in_new_ctxt=True)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                return self._pyfhel.add_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be either PyCtxt or PyPtxt")
    
    def __radd__(self, other): return self.__add__(other)
    def __iadd__(self, other):
        """Sums this ciphertext with either another PyCtx or a PyPtxt plaintext.
        
        Sums with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Second summand.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.add(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            self._pyfhel.add_plain(self, other, in_new_ctxt=False)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                self._pyfhel.add_plain(self, other, in_new_ctxt=False)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                self._pyfhel.add_plain(self, other, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> other summand must be either PyCtxt or PyPtxt")
        return self


    def __sub__(self, other):
        """__sub__(other)
        
        Substracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Substracts with a PyPtxt/PyCtxt, storing the result in a new ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Substrahend, to be substracted from this ciphertext.
        Returns:
            PyCtxt: Ciphertext resulting of substraction

        Raise:
            TypeError: if other doesn't have a valid type.
            
        See Also:
            :func:`~Pyfhel.Pyfhel.sub`
        """
        if isinstance(other, PyCtxt):
            return self._pyfhel.sub(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.sub_plain(self, other, in_new_ctxt=True)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                return self._pyfhel.sub_plain(self, other, in_new_ctxt=True)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                return self._pyfhel.sub_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
    
    def __rsub__(self, other): return self.__sub__(other)
    def __isub__(self, other): 
        """Substracts this ciphertext with either another PyCtxt or a PyPtxt plaintext.
        
        Substracts with a PyPtxt/PyCtxt, storing the result in this ciphertext.

        Args:
            other (PyCtxt, PyPtxt): Substrahend, to be substracted from this ciphertext.
            
        Raise:
            TypeError: if other doesn't have a valid type.
        """
        if isinstance(other, PyCtxt):
            self._pyfhel.sub(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            self._pyfhel.sub_plain(self, other, in_new_ctxt=False)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                self._pyfhel.sub_plain(self, other, in_new_ctxt=False)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                self._pyfhel.sub_plain(self, other, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> substrahend must be either PyCtxt or PyPtxt")
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
        if isinstance(other, PyCtxt):
            return self._pyfhel.multiply(self, other, in_new_ctxt=True)
        elif isinstance(other, PyPtxt):
            return self._pyfhel.multiply_plain(self, other, in_new_ctxt=True)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                return self._pyfhel.multiply_plain(self, other, in_new_ctxt=True)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                return self._pyfhel.multiply_plain(self, other, in_new_ctxt=True)
        else:
            raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt, PyPtxt or int|float"
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
        if isinstance(other, PyCtxt):
            self._pyfhel.multiply(self, other, in_new_ctxt=False)
        elif isinstance(other, PyPtxt):
            self._pyfhel.multiply_plain(self, other, in_new_ctxt=False)
        elif isinstance(other, (int, float)):
            if self._scheme == SCHEME_t.BFV:
                other = self._pyfhel.encodeInt(int(other))
                self._pyfhel.multiply_plain(self, other, in_new_ctxt=False)
            elif self._scheme == SCHEME_t.CKKS:
                other = self._pyfhel.encodeFrac(float(other))
                self._pyfhel.multiply_plain(self, other, in_new_ctxt=False)
        else:
            raise TypeError("<Pyfhel ERROR> multiplicand must be either PyCtxt, PyPtxt or int|float"
                            "(is %s instead)"%(type(other)))
        return self


    def __truediv__(self, divisor):
        """__truediv__(divisor)
        
        Multiplies this ciphertext with the inverse of divisor.
        
        This operation can only be done with plaintexts. Division between 
        two Ciphertexts is not possible.

        For BFV Integer Scheme, the inverse is calculated as:
            inverse -> (divisor * inverse) mod p = 1

        For CKKS Fractional scheme, the inverse is calculated as 1/divisor.

        Args:
            divisor (int, float, PyPtxt): divisor for the operation.
        """
        if isinstance(divisor, PyPtxt):
            divisor = divisor.decode()
        if not isinstance(divisor, (int, float)):
            raise TypeError("<Pyfhel ERROR> divisor must be float, int"
                            "or PyPtxt with BFV/CKKS scheme (is %s:%s instead)"
                            %(str(divisor),type(divisor)))
        # Compute inverse. Int: https://stackoverflow.com/questions/4798654
        if self._scheme == SCHEME_t.BFV:
            divisor = int(divisor)
            p = self._pyfhel.getp()
            inverse = pow(divisor, p-2, p)
            inversePtxt = self._pyfhel.encodeInt(inverse)
        elif self._scheme == SCHEME_t.CKKS: # float. Standard inverse
            inverse = 1/float(divisor)
            inversePtxt = self._pyfhel.encodeFrac(inverse)
        else:
            raise TypeError("<Pyfhel ERROR> dividend scheme doesn't support"
                            "division (%s)"%(self._scheme))
        return self._pyfhel.multiply_plain(self, inversePtxt, in_new_ctxt=True)

    def __itruediv__(self, divisor):
        """Multiplies this ciphertext with the inverse of divisor.
        
        This operation can only be done with plaintexts. Division between 
        two Ciphertexts is not possible.

        For BFV Integer Scheme, the inverse is calculated as:
            inverse -> (divisor * inverse) mod p = 1

        For CKKS Fractional scheme, the inverse is calculated as 1/divisor.

        Args:
            divisor (int, float, PyPtxt): divisor for the operation.
        """
        if isinstance(divisor, PyPtxt):
            divisor = divisor.decode()
        if not isinstance(divisor, (int, float)):
            raise TypeError("<Pyfhel ERROR> divisor must be float, int"
                            "or PyPtxt with BFV/CKKS scheme (is %s:%s instead)"
                            %(str(divisor),type(divisor)))
        # Compute inverse. Int: https://stackoverflow.com/questions/4798654
        if self._scheme == SCHEME_t.BFV:
            divisor = int(divisor)
            p = self._pyfhel.getp()
            inverse = pow(divisor, p-2, p)
            inversePtxt = self._pyfhel.encodeInt(inverse)
        elif self._scheme == SCHEME_t.CKKS: # float. Standard inverse
            inverse = 1/float(divisor)
            inversePtxt = self._pyfhel.encodeFrac(inverse)
        else:
            raise TypeError("<Pyfhel ERROR> dividend scheme doesn't support"
                            "division (%s)"%(self._scheme))
        self._pyfhel.multiply_plain(self, inversePtxt, in_new_ctxt=False)
        return self

                                    
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

        Requires valid relinearization keys with a bitcount higher than the
        current size of this ciphertext.

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
        return self.size()
    
    def __repr__(self):
        """__repr__()
        
        Prints information about the current ciphertext"""
        sk_not_empty = self._pyfhel is not None and not self._pyfhel.is_secretKey_empty()
        return "<Pyfhel Ciphertext at {}, scheme={}, size={}/{}, noiseBudget={}>".format(
                hex(id(self)),
                to_SCHEME_t(self._scheme).name,
                self.size(),
                self.size_capacity(),
                self._pyfhel.noiseLevel(self) if sk_not_empty else "-"
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
        self._pyfhel.encrypt(value, self)
    
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
        return self._pyfhel.decrypt(self, decode_value=True)
