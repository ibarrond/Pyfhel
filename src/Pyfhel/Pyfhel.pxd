# distutils: language = c++

# -------------------------------- CIMPORTS -----------------------------------
# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdint cimport int64_t

# Import our own wrapper for iostream classes, used for I/O ops
from iostream cimport istream, ostream, ifstream, ofstream   

from Afhel cimport Plaintext
from Afhel cimport Ciphertext
from Afhel cimport Afseal

# Import the Cython Plaintext and Cyphertext classes
from PyPtxt cimport PyPtxt
from PyCtxt cimport PyCtxt

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class Pyfhel:
    cdef Afseal* afseal           # The C++ methods are accessed via a pointer
    cpdef void ContextGen(self, long p, long m, bool flagBatching,
                  long base, long sec, int intDigits, int fracDigits) except +
    cpdef void KeyGen(self)
    cpdef PyCtxt encryptInt(self, int64_t value, PyCtxt ctxt)
    cpdef PyCtxt encryptFrac(self, double value, PyCtxt ctxt)
    cpdef PyCtxt encryptBatch(self, vector[int64_t] vec, PyCtxt ctxt)
    cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt)
    cpdef decrypt(self, PyCtxt ctxt, PyPtxt ptxt)