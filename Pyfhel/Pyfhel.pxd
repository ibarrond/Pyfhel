# distutils: language = c++
#cython: language_level=3, boundscheck=False

# -------------------------------- CIMPORTS -----------------------------------
# import both numpy and the Cython declarations for numpy
cimport numpy as np

# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp.cast cimport reinterpret_cast
from libcpp.memory cimport shared_ptr, dynamic_pointer_cast
from libcpp cimport bool
from numpy cimport int64_t, uint64_t

# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.utils.iostream cimport istream, ostream, ifstream, ofstream, ostringstream, stringstream, binary

from Pyfhel.Afhel.Afhel cimport *

# Import the Cython Plaintext, Ciphertext and Poly classes
from Pyfhel.PyPtxt cimport PyPtxt
from Pyfhel.PyCtxt cimport PyCtxt
from Pyfhel.PyPoly cimport PyPoly

# ---------------------------- CYTHON DECLARATION ------------------------------
cdef class Pyfhel:
    cdef Afhel* afseal           # The C++ methods are accessed via a pointer
    cdef int _sec
    cdef vector[int] _qi
    cdef double _scale
    # =========================== CRYPTOGRAPHY =================================
    # CONTEXT & KEY GENERATION
    cpdef void contextGen(self,
            str scheme, int n, int64_t q=*, int t_bits=*, int64_t t=*, int sec=*,
            double scale=*, int scale_bits=*,  vector[int] qi =*) 
    cpdef void keyGen(self) 
    cpdef void relinKeyGen(self) 
    cpdef void rotateKeyGen(self) 
    
    # ENCRYPTION
    cpdef PyCtxt encryptInt(self, int64_t[:] arr, PyCtxt ctxt=*)
    cpdef PyCtxt encryptFrac(self, double[:] arr, PyCtxt ctxt=*,
                                        double scale=*, int scale_bits=*) 
    cpdef PyCtxt encryptComplex(self, complex[:] arr, PyCtxt ctxt=*, 
                                        double scale=*, int scale_bits=*) 
    cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt=*) 
    # vectorized
    cpdef np.ndarray[object, ndim=1] encryptAInt(self, int64_t[:,::1] arr) 
    cpdef np.ndarray[object, ndim=1] encryptAFrac(self, double[:,::1] arr,
                                        double scale=*, int scale_bits=*) 
    cpdef np.ndarray[object, ndim=1] encryptAComplex(self, complex[:,::1] arr,
                                        double scale=*, int scale_bits=*) 
    cpdef np.ndarray[object, ndim=1] encryptAPtxt(self, PyPtxt[:] ptxt)  

    # DECRYPTION
    cpdef np.ndarray[int64_t, ndim=1] decryptInt(self, PyCtxt ctxt) 
    cpdef np.ndarray[double, ndim=1] decryptFrac(self, PyCtxt ctxt) 
    cpdef np.ndarray[complex, ndim=1] decryptComplex(self, PyCtxt ctxt) 
    cpdef PyPtxt decryptPtxt(self, PyCtxt ctxt, PyPtxt ptxt=*) 
    # vectorized
    cpdef np.ndarray[int64_t, ndim=2] decryptAInt(self, PyCtxt ctxt) 
    cpdef np.ndarray[double, ndim=2] decryptAFrac(self, PyCtxt ctxt) 
    cpdef np.ndarray[double, ndim=2] decryptAComplex(self, PyCtxt ctxt) 
    cpdef np.ndarray[object, ndim=1] decryptAPtxt(self, PyCtxt ctxt) 
    
    # NOISE LEVEL    
    cpdef int noise_level(self, PyCtxt ctxt)
    
    # ============================= ENCODING ===================================
    # ENCODE
    cpdef PyPtxt encodeInt(self, int64_t[::1] arr, PyPtxt ptxt=*) 
    cpdef PyPtxt encodeFrac(self, double[::1] arr, PyPtxt ptxt=*,
                                double scale=*, int scale_bits=*, ) 
    cpdef PyPtxt encodeComplex(self, complex[::1] arr, PyPtxt ptxt=*,
                                double scale=*, int scale_bits=*) 
    # vectorized
    cpdef np.ndarray[object, ndim=1] encodeAInt(self, int64_t[:,::1] arr) 
    cpdef np.ndarray[object, ndim=1] encodeAFrac(self, double[:,::1] arr, 
                                    double scale=*, int scale_bits=*) 
    cpdef np.ndarray[object, ndim=1] encodeAComplex(self, complex[:,::1] arr,
                                    double scale=*, int scale_bits=*) 

    # DECODE
    cpdef np.ndarray[int64_t, ndim=1] decodeInt(self, PyPtxt ptxt) 
    cpdef np.ndarray[double, ndim=1] decodeFrac(self, PyPtxt ptxt) 
    cpdef np.ndarray[complex, ndim=1] decodeComplex(self, PyPtxt ptxt) 
    # vectorized
    cpdef np.ndarray[int64_t, ndim=2] decodeAInt(self, PyPtxt[:] ptxt) 
    cpdef np.ndarray[double, ndim=2] decodeAFrac(self, PyPtxt[:] ptxt) 
    cpdef np.ndarray[complex, ndim=2] decodeAComplex(self, PyPtxt[:] ptxt) 
    
    # RELINEARIZE
    cpdef void relinearize(self, PyCtxt ctxt) 

    # ============================ OPERATIONS ==================================
    cpdef PyCtxt negate(self, PyCtxt ctxt, bool in_new_ctxt=*) 
    cpdef PyCtxt square(self, PyCtxt ctxt, bool in_new_ctxt=*) 
    cpdef PyCtxt add(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) 
    cpdef PyCtxt add_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) 
    cpdef PyCtxt sub(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) 
    cpdef PyCtxt sub_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) 
    cpdef PyCtxt multiply(self, PyCtxt ctxt, PyCtxt ctxt_other, bool in_new_ctxt=*) 
    cpdef PyCtxt multiply_plain(self, PyCtxt ctxt, PyPtxt ptxt, bool in_new_ctxt=*) 
    cpdef PyCtxt rotate(self, PyCtxt ctxt, int k, bool in_new_ctxt=*) 
    cpdef PyCtxt power(self, PyCtxt ctxt, uint64_t expon, bool in_new_ctxt=*) 
    # ckks
    cpdef void rescale_to_next(self, PyCtxt ctxt) 

    # ================================ I/O =====================================
    #FILES
    cpdef size_t save_context(self, fileName, str compr_mode=*) 
    cpdef size_t load_context(self, fileName) 

    cpdef size_t save_public_key(self, fileName, str compr_mode=*) 
    cpdef size_t load_public_key(self, fileName) 

    cpdef size_t save_secret_key(self, fileName, str compr_mode=*) 
    cpdef size_t load_secret_key(self, fileName) 

    cpdef size_t save_relin_key(self, fileName, str compr_mode=*) 
    cpdef size_t load_relin_key(self, fileName) 

    cpdef size_t save_rotate_key(self, fileName, str compr_mode=*) 
    cpdef size_t load_rotate_key(self, fileName) 


    #BYTES
    cpdef bytes to_bytes_context(self, str compr_mode=*) 
    cpdef size_t from_bytes_context(self, bytes content) 

    cpdef bytes to_bytes_public_key(self, str compr_mode=*) 
    cpdef size_t from_bytes_public_key(self, bytes content) 

    cpdef bytes to_bytes_secret_key(self, str compr_mode=*) 
    cpdef size_t from_bytes_secret_key(self, bytes content) 

    cpdef bytes to_bytes_relin_key(self, str compr_mode=*) 
    cpdef size_t from_bytes_relin_key(self, bytes content) 

    cpdef bytes to_bytes_rotate_key(self, str compr_mode=*) 
    cpdef size_t from_bytes_rotate_key(self, bytes content) 
    
    # ============================== AUXILIARY =================================
    cpdef long maxBitCount(self, long poly_modulus_degree, int sec_level) 

    # GETTERS
    cpdef bool batchEnabled(self) 
    cpdef size_t get_nSlots(self) 
    cpdef uint64_t get_plain_modulus(self) 
    cpdef size_t get_poly_modulus_degree(self) 
    cpdef scheme_t get_scheme(self) 
    
    cpdef bool is_secret_key_empty(self) 
    cpdef bool is_public_key_empty(self) 
    cpdef bool is_rotate_key_empty(self) 
    cpdef bool is_relin_key_empty(self) 
    cpdef bool is_context_empty(self) 

    # ============================ POLYNOMIAL =================================
    cpdef PyPoly empty_poly(self, PyCtxt ref) 
    cpdef PyPoly poly_from_ciphertext(self, PyCtxt ctxt, size_t i) 
    cpdef PyPoly poly_from_plaintext(self, PyCtxt ref, PyPtxt ptxt) 
    cpdef PyPoly poly_from_coeff_vector(self, vector[cy_complex] coeff_vector, PyCtxt ref) 
    cpdef list polys_from_ciphertext(self, PyCtxt ctxt) 

    cpdef PyPoly poly_add(self, PyPoly p, PyPoly p_other, bool in_new_poly=*) 
    cpdef PyPoly poly_subtract(self, PyPoly p, PyPoly p_other, bool in_new_poly=*) 
    cpdef PyPoly poly_multiply(self, PyPoly p, PyPoly p_other, bool in_new_poly=*) 
    cpdef PyPoly poly_invert(self, PyPoly p, bool in_new_poly=*) 

    cpdef void poly_to_ciphertext(self, PyPoly p, PyCtxt ctxt, size_t i) 
    cpdef void poly_to_plaintext(self, PyPoly p, PyPtxt ptxt) 
    
# --------------------------------- UTILS --------------------------------------
cpdef to_Scheme_t(object scheme)
cpdef to_Backend_t(object backend)
cpdef np.ndarray[dtype=np.int64_t, ndim=1] vec_to_array_i(vector[int64_t] vec)
cpdef np.ndarray[dtype=double, ndim=1] vec_to_array_f(vector[double] vec)
cdef shared_ptr[AfsealCtxt] _dyn_c(shared_ptr[AfCtxt] c)