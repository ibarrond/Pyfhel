# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS -----------------------------------
# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp cimport bool
from libc.stdint cimport int64_t
from libc.stdint cimport uint64_t

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream   

from Pyfhel.Afhel cimport Plaintext
from Pyfhel.Afhel cimport Ciphertext
from Pyfhel.Afhel cimport Afseal

# Import the Cython Plaintext and Cyphertext classes
from Pyfhel.PyPtxt cimport PyPtxt
from Pyfhel.PyCtxt cimport PyCtxt

# Encoding types: 0-UNDEFINED, 1-INTEGER, 2-FRACTIONAL, 3-BATCH
from Pyfhel.util cimport ENCODING_T


# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class Pyfhel:
    cdef Afseal* afseal           # The C++ methods are accessed via a pointer
    
    # =========================== CRYPTOGRAPHY =================================
    cpdef contextGen(self, long p, long m=*, bool flagBatching=*, long base=*,
                     long sec=*, int intDigits=*, int fracDigits=*) except +
    cpdef void keyGen(self) except +
    cpdef void rotateKeyGen(self, int bitCount) except +
    cpdef void relinKeyGen(self, int bitCount, int size) except +
    
    cpdef PyCtxt encryptInt(self, int64_t value, PyCtxt ctxt=*) except +
    cpdef PyCtxt encryptFrac(self, double value, PyCtxt ctxt=*) except +
    cpdef PyCtxt encryptBatch(self, vector[int64_t] vec, PyCtxt ctxt=*) except +
    cpdef PyCtxt encryptArray(self, int64_t[::1] arr, PyCtxt ctxt=*) except +
    cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt=*) except +
    
    cpdef int64_t decryptInt(self, PyCtxt ctxt) except +
    cpdef double decryptFrac(self, PyCtxt ctxt) except +
    cpdef vector[int64_t] decryptBatch(self, PyCtxt ctxt) except +
    cpdef int64_t[::1] decryptArray(self, PyCtxt ctxt) except +
    cpdef PyPtxt decryptPtxt(self, PyCtxt ctxt, PyPtxt ptxt=*) except +
    
    cpdef void relinearize(self, PyCtxt ctxt) except +
    
    cpdef int noiseLevel(self, PyCtxt ctxt) except +
    
    # ============================= ENCODING ===================================
    cpdef PyPtxt encodeInt(self, int64_t value, PyPtxt ptxt=*) except +
    cpdef PyPtxt encodeFrac(self, double value, PyPtxt ptxt=*) except +
    cpdef PyPtxt encodeBatch(self, vector[int64_t] vec, PyPtxt ptxt=*) except +
    cpdef PyPtxt encodeArray(self, int64_t[::1] arr, PyPtxt ptxt=*) except +
    
    cpdef int64_t decodeInt(self, PyPtxt ptxt) except +
    cpdef double decodeFrac(self, PyPtxt ptxt) except +
    cpdef vector[int64_t] decodeBatch(self, PyPtxt ptxt) except +
    cpdef int64_t[::1] decodeArray(self, PyPtxt ptxt) except +
    
    # ============================ OPERATIONS ==================================
    cpdef PyCtxt square(self, PyCtxt ctxt, bool in_new_ctxt=*) except +
    cpdef PyCtxt negate(self, PyCtxt ctxt, bool in_new_ctxt=*) except +
    cpdef PyCtxt add(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) except +
    cpdef PyCtxt add_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) except +
    cpdef PyCtxt sub(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) except +
    cpdef PyCtxt sub_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) except +
    cpdef PyCtxt multiply(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) except +
    cpdef PyCtxt multiply_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) except +
    cpdef PyCtxt rotate(self, PyCtxt ctxt, int k, bool in_new_ctxt=*) except +
    cpdef PyCtxt power(self, PyCtxt ctxt, uint64_t expon, bool in_new_ctxt=*) except +
    cpdef PyCtxt polyEval(self, PyCtxt ctxt, vector[int64_t] coeffPoly, bool in_new_ctxt=*) except +
    cpdef PyCtxt polyEval_double (self, PyCtxt ctxt, vector[double] coeffPoly, bool in_new_ctxt=*) except +

    
    # ================================ I/O =====================================
    cpdef bool saveContext(self, str fileName) except +
    cpdef bool restoreContext(self, str fileName) except +

    cpdef bool savepublicKey(self, str fileName) except +
    cpdef bool restorepublicKey(self, str fileName) except +

    cpdef bool savesecretKey(self, str fileName) except +
    cpdef bool restoresecretKey(self, str fileName) except +

    cpdef bool saverelinKey(self, str fileName) except +
    cpdef bool restorerelinKey(self, str fileName) except +

    cpdef bool saverotateKey(self, str fileName) except +
    cpdef bool restorerotateKey(self, str fileName) except +

    
    # ============================== AUXILIARY =================================
    cpdef bool batchEnabled(self) except +
    cpdef long relinBitCount(self) except +

    # GETTERS
    cpdef int getnSlots(self) except +
    cpdef int getp(self) except +
    cpdef int getm(self) except +
    cpdef int getbase(self) except +
    cpdef int getsec(self) except + 
    cpdef int getintDigits(self) except +
    cpdef int getfracDigits(self) except +
    cpdef bool getflagBatch(self) except +
    
