# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.string cimport string
from libcpp.complex cimport complex as c_complex
from libcpp cimport bool

# Used for all kinds of operations
from Pyfhel.Pyfhel cimport *

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.utils.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import AfsealPoly class
from Pyfhel.Afhel.Afhel cimport AfPoly, AfsealPoly, scheme_t, backend_t, cy_complex

# ------------------------------- DECLARATION ---------------------------------

cdef class PyPoly:
    cdef AfsealPoly* _afpoly
    cdef Pyfhel _pyfhel
    cdef scheme_t _scheme
    cdef backend_t _backend
    cpdef vector[cy_complex] to_coeff_list(self)
    cpdef cy_complex get_coeff(self, size_t i)
    cpdef void set_coeff(self, cy_complex&val, size_t i)
    cpdef void check_afpoly(self)
    cpdef void from_coeff_list(self, vector[cy_complex] coeff_list, PyCtxt ref)

    # Serialize
    cpdef void save(self, str fileName)
    cpdef void load(self, str fileName, encoding)
    cpdef bytes to_bytes(self)
    cpdef void from_bytes(self, bytes content, encoding)
