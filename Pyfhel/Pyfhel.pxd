# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS -----------------------------------
# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp cimport bool
from numpy cimport int64_t, uint64_t

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream,ostringstream, stringstream, binary

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
    #FILES
    cpdef bool saveContext(self, fileName) except +
    cpdef bool restoreContext(self, fileName) except +

    cpdef bool savepublicKey(self, fileName) except +
    cpdef bool restorepublicKey(self, fileName) except +

    cpdef bool savesecretKey(self, fileName) except +
    cpdef bool restoresecretKey(self, fileName) except +

    cpdef bool saverelinKey(self, fileName) except +
    cpdef bool restorerelinKey(self, fileName) except +

    cpdef bool saverotateKey(self, fileName) except +
    cpdef bool restorerotateKey(self, fileName) except +


    #BYTES
    cpdef bytes to_bytes_context(self) except +
    cpdef bool from_bytes_context(self, bytes content) except +

    cpdef bytes to_bytes_publicKey(self) except +
    cpdef bool from_bytes_publicKey(self, bytes content) except +

    cpdef bytes to_bytes_secretKey(self) except +
    cpdef bool from_bytes_secretKey(self, bytes content) except +

    cpdef bytes to_bytes_relinKey(self) except +
    cpdef bool from_bytes_relinKey(self, bytes content) except +

    cpdef bytes to_bytes_rotateKey(self) except +
    cpdef bool from_bytes_rotateKey(self, bytes content) except +
    
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
    
    cpdef bool is_secretKey_empty(self) except+
    cpdef bool is_publicKey_empty(self) except+
    cpdef bool is_rotKey_empty(self) except+
    cpdef bool is_relinKey_empty(self) except+
    cpdef bool is_context_empty(self) except+


# --------------------------------- UTILS --------------------------------------
cpdef to_ENCODING_t(encoding) except +
cpdef str _to_valid_file_str(fileName, bool check=*) except +
