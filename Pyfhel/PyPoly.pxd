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
from Pyfhel.iostream cimport ifstream, ofstream, ostringstream, stringstream, binary

# Import AfsealPoly class
from Pyfhel.Afhel cimport AfsealPoly, cy_complex

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util cimport ENCODING_T
# ------------------------------- DECLARATION ---------------------------------

cdef class PyPoly:
    cdef AfsealPoly* _afpoly
    cdef Pyfhel _pyfhel
    cdef ENCODING_T _encoding
    cpdef vector[cy_complex] to_coeff_list(self) except+
    cpdef cy_complex get_coeff(self, size_t i) except+
    cpdef void set_coeff(self, cy_complex&val, size_t i) except+
    cpdef void check_afpoly(self) except+
    cpdef void from_coeff_list(self, vector[cy_complex] coeff_list, PyCtxt ref) except+

    # Serialize
    cpdef void to_file(self, fileName) except +
    cpdef void from_file(self, fileName, encoding) except +
    cpdef void save(self, str fileName) except +
    cpdef void load(self, str fileName, encoding) except +
    cpdef bytes to_bytes(self) except +
    cpdef void from_bytes(self, bytes content, encoding) except +
