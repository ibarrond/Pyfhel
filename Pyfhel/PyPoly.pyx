"""PyPoly. Internal Polynomial of Pyfhel, Python For Homomorphic Encryption Libraries.
"""
# -------------------------------- IMPORTS ------------------------------------
# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

from .utils.Scheme_t import Scheme_t
from .utils.Backend_t import Backend_t

# ----------------------------- IMPLEMENTATION --------------------------------
cdef class PyPoly:
    """Polynomial class of Pyfhel with the underlying data of a PyCtxt/PyPtxt.

    Attributes:
        other_ptxt (PyPtxt, optional): Other PyPtxt to deep copy
    
    """
    
    def __cinit__(
        self,
        PyPoly other=None,
        PyCtxt ref=None,
        PyPtxt ptxt=None,
        size_t index=0,
    ):
        if other is not None and other._afpoly is not NULL:   # Copy constructor if there is a PyPoly to copy
            self._afpoly = new AfsealPoly(deref(other._afpoly))
            if other._pyfhel is not None:
                self._pyfhel = other._pyfhel
        else:
            assert ref is not None and ref._pyfhel is not None and ref._pyfhel.afseal is not NULL,\
                "Missing reference PyCtxt `ref` with initialized _pyfhel member"
            if index is not None:   # Construct from selected Poly in PyCtxt `ref`
                self._afpoly = new AfsealPoly(deref(<Afseal*>ref._pyfhel.afseal), deref(_dyn_c(ref._ptr_ctxt)), <size_t>index)  
                self._pyfhel = ref._pyfhel
            elif ptxt is not None:  # Construct from Poly in PyPtxt `ptxt`
                self._afpoly =\
                    new AfsealPoly(deref(<Afseal*>ref._pyfhel.afseal), deref(<AfsealPtxt*>ptxt._ptr_ptxt), deref(_dyn_c(ref._ptr_ctxt)))  
                self._pyfhel = ptxt._pyfhel
            else:                   # Base constructor
                self._afpoly =\
                    new AfsealPoly(deref(<Afseal*>ref._pyfhel.afseal), deref(_dyn_c(ref._ptr_ctxt)))  
                self._pyfhel = ref._pyfhel
                
    def __init__(
        self,
        PyPoly other=None,
        PyCtxt ref=None,
        PyPtxt ptxt=None,
        size_t index=0,
    ):
        """Initializes a PyPoly polynomial.
        
        To fill the polynomial during initialization you can either:
            - Provide a PyPoly to deep copy. 
            - Provide a reference PyCtxt and (optionally) an index for the i-th 
                    polynomial in the cipertext or (optionally) a source PyPtxt.

        Attributes:
            other (PyPoly, optional): Other PyPoly to deep copy.
            ref (PyCtxt, optional): PyCtxt instance needed as reference.
            size_t (int, optional): extract i-th polynomial from ciphertext `ref`.
            ptxt (PyPtxt, optional): plaintext used as source.
        """
        pass

    def __dealloc__(self):
        if self._afpoly != NULL:
            del self._afpoly
            
    @property
    def _scheme(self):
        """_scheme: returns the scheme type.
        
        Can be set to: 0-None, 1-BFV, 2-CKKS, 3-BGV.

        See Also:
            :func:`~Pyfhel.utils.to_scheme_t`

        :meta public:
        """
        return Scheme_t(self._scheme)
    
    @_scheme.setter
    def _scheme(self, new_scheme):
        if not isinstance(new_scheme, scheme_t):
            raise TypeError("<Pyfhel ERROR> Scheme type of PyPoly must be scheme_t")        
        self._scheme = new_scheme
        
    @_scheme.deleter
    def _scheme(self):
        self._scheme = Scheme_t.none
              
        
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
    def coeff_modulus_count(self):
        self.check_afpoly()
        return self._afpoly.get_coeff_modulus_count()

    @property
    def coeff_count(self):
        self.check_afpoly()
        return self._afpoly.get_coeff_count()


    cpdef vector[cy_complex] to_coeff_list(self):
        """List of complex coefficients of the polynomial"""
        self.check_afpoly()
        return self._afpoly.to_coeff_list(deref(<Afseal*>self._pyfhel.afseal))
    


    
    # =========================================================================
    # ================================== I/O ==================================
    # =========================================================================
    cpdef void save(self, str fileName):
        """save(str fileName)
        
        Save the polynomial into a file. The file can new one or
        exist already, in which case it will be overwriten.

        Args:
            fileName: (str) File where the polynomial will be stored.

        Return:
            None            
        """
        raise NotImplementedError("No PyPoly Serialization avaliable yet")

    cpdef bytes to_bytes(self):
        """to_bytes()

        Serialize the polynomial into a binary/bytes string.

        Return:
            bytes: serialized polynomial
        """
        raise NotImplementedError("No PyPoly Serialization avaliable yet")

    cpdef void load(self, str fileName, encoding):
        """load(self, str fileName, encoding)
        
        Load the polynomial from a file.

        Args:
            fileName: (str) Valid file where the polynomial is retrieved from.
            encoding: (str, type, int, scheme_t) One of the following:
              * ('int', 'integer', int, 1, scheme_t.INTEGER) -> integer encoding.
              * ('float', 'double', float, 2, scheme_t.FRACTIONAL) -> fractional encoding.
              
        Return:
            None

        See Also:
            :func:`~Pyfhel.utils.to_scheme_t`
        """
        raise NotImplementedError("No PyPoly Serialization avaliable yet")

    cpdef void from_bytes(self, bytes content, encoding):
        """from_bytes(bytes content)

        Recover the serialized polynomial from a binary/bytes string.

        Args:
            content: (:obj:`bytes`) Python bytes object containing the PyPoly.
            encoding: (:obj: `str`) String or type describing the encoding:
              * ('int', 'integer', int, 1, scheme_t.INTEGER) -> integer encoding.
              * ('float', 'double', float, 2, scheme_t.FRACTIONAL) -> fractional encoding.
              * ('array', 'batch', 'matrix', list, 3, scheme_t.BATCH) -> batch encoding.
        """
        raise NotImplementedError("No PyPoly Serialization avaliable yet")



    # =========================================================================
    # ============================ ENCR/DECR/CMP ==============================
    # =========================================================================

    def __list__(self):
        return self.to_coeff_list()
    
    # def __repr__(self):
    
    def __len__(self):
        self.check_afpoly()
        return self._afpoly.get_coeff_count()

    def __getitem__(self, size_t i):
        self.check_afpoly()
        if i >= self.__len__():
            raise IndexError("PyPoly error: coefficient index out of bounds")
        return self._afpoly.get_coeff(deref(<Afseal*>self._pyfhel.afseal), i)
    
    def __setitem__(self, size_t i, cy_complex coeff):
        """"""
        self.check_afpoly()
        if i >= self.__len__():
            raise IndexError("PyPoly error: coefficient index out of bounds")
        self._afpoly.set_coeff(deref(<Afseal*>self._pyfhel.afseal), coeff, i)

    def __iter__(self):
        """Creates an iterator to extract all coefficients"""
        self.check_afpoly()
        return (self._afpoly.get_coeff(deref(<Afseal*>self._pyfhel.afseal), i) for i in range(self._afpoly.get_coeff_count()))

    cpdef cy_complex get_coeff(self, size_t i):
        """Gets the chosen coefficient in position i.
        
        Arguments:
            i (int): coefficient position
            
        Return:
            complex: coefficient value
        """
        return self._afpoly.get_coeff(deref(<Afseal*>self._pyfhel.afseal), i)

    cpdef void set_coeff(self, cy_complex &coeff, size_t i):
        """Sets the given complex value as coefficient in position i.
        
        Arguments:
            coeff (complex): new coefficient value
            
        Return:
            None
        """
        self.check_afpoly()
        self._afpoly.set_coeff(deref(<Afseal*>self._pyfhel.afseal), coeff, i)
    
    cpdef void from_coeff_list(self, vector[cy_complex] coeff_list, PyCtxt ref):
        """Sets all the coefficients at once.
        
        Arguments:
            coeff_list (List(complex)): list of coefficients
            
        Return:
            int, float, np.array: value decrypted.
   
        See Also:
            :func:`~Pyfhel.Pyfhel.decode`
        """
        raise NotImplementedError("Missing intermediate function")

    cpdef void check_afpoly(self):
        """Checks if afpoly was initialized or not"""
        if self._afpoly == NULL:
            raise AttributeError("PyPoly member _afpoly not initialized")


    # =========================================================================
    # ============================= OPERATIONS ================================
    # =========================================================================
        
    def __add__(self, PyPoly other):
        """Sums this pollynomial with another polynomial.
        
        Sums with a PyPoly, storing the result in a new PyPoly.

        Args:
            other (PyPoly): Second summand.

        Returns:
            PyPoly: Polynomial resulting of addition.

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_add`
        """
        return self._pyfhel.poly_add(self, other, in_new_poly=True)
    
    def __radd__(self, other): return self.__add__(other)
    def __iadd__(self, other):
        """Sums this pollynomial with another polynomial inplace.
        
        Sums with a PyPoly, storing the result in this PyPoly.

        Args:
            other (PyPoly): Second summand.

        Returns:
            None

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_add`
        """
        return self._pyfhel.poly_add(self, other, in_new_poly=False)


    def __sub__(self, other):
        """Subtracts other polynomial from this polynomial.
        
        Subtracts with a PyPoly, storing the result in this PyPoly.

        Args:
            other (PyPoly): Substrahend, to be subtracted from this polynomial.

        Returns:
            PyPoly: Polynomial resulting of subtraction.

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_subtract`
        """
        return self._pyfhel.poly_subtract(self, other, in_new_poly=False)
    
    def __rsub__(self, other): return self.__sub__(other)
    def __isub__(self, other): 
        """Subtracts other pollynomial from this polynomial inplace.
        
        Subtracts with a PyPoly, storing the result in this PyPoly.

        Args:
            other (PyPoly): Substrahend, to be subtracted from this polynomial.

        Returns:
            None

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_subtract`
        """
        return self._pyfhel.poly_subtract(self, other, in_new_poly=False)
                        
    def __mul__(self, other):
        """Multiplies this polynomial with another polynomial.
        
        Multiplies with a PyPoly, storing the result in a new PyPoly.

        Args:
            other (PyPoly): multiplier polynomial.

        Returns:
            PyPoly: Polynomial resulting of multiplication.

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_multiply`
        """
        return self._pyfhel.poly_multiply(self, other, in_new_poly=True)
     
    def __rmul__(self, other): return self.__mul__(other)
    def __imul__(self, other): 
        """Multiplies this polynomial with another polynomial inplace.
        
        Multiplies with a PyPoly, storing the result in this PyPoly.

        Args:
            other (PyPoly): multiplier polynomial.

        Returns:
            PyPoly: Polynomial resulting of multiplication.

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_multiply`
        """
        return self._pyfhel.poly_multiply(self, other, in_new_poly=False)

    def __invert__(self):
        """Inverts this polynomial.

        See Also:
            :func:`~Pyfhel.Pyfhel.poly_invert`
        """
        return self._pyfhel.poly_invert(self, in_new_poly=True)