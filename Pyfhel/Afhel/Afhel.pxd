# distutils: language = c++
# distutils: sources = ../SEAL/SEAL/seal/plaintext.cpp ../SEAL/SEAL/seal/ciphertext.cpp ../Afhel/Afseal.cpp
#cython: language_level=3, boundscheck=False

# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp.memory cimport shared_ptr, dynamic_pointer_cast
from libcpp.map cimport map as cpp_map
from libcpp.complex cimport complex as c_complex
from libcpp cimport bool
#from numpy cimport int64_t, uint64_t, uint8_t
        
# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.utils.iostream cimport istream, ostream, ifstream, ofstream       

ctypedef long long int64_t
ctypedef unsigned long long uint64_t
ctypedef unsigned char uint8_t
ctypedef c_complex[double] cy_complex

#===============================================================================
#============================ SEAL - C++ API ===================================
#===============================================================================
# SEAL plaintext class        
cdef extern from "seal/plaintext.h" namespace "seal" nogil:
    cdef cppclass Plaintext:
        Plaintext() except +
        Plaintext(const Plaintext &copy) except +
        bool is_zero() except +
        string to_string() except +
        inline bool is_ntt_form()
        double scale() except +
        
# SEAL ciphertext class        
cdef extern from "seal/ciphertext.h" namespace "seal" nogil:
    cdef cppclass Ciphertext:
        Ciphertext() except +
        Ciphertext(const Ciphertext &copy) except +
        int size_capacity() except +
        int size() except +
        double scale() except +

#===============================================================================
#============================ Afhel - C++ API ==================================
#===============================================================================
cdef extern from "Afhel.h" nogil:
    # ============================== Enums =====================================
    # FHE Scheme
    cdef enum class scheme_t(uint8_t):
        none,
        bfv
        ckks
    cdef cpp_map scheme_t_str[scheme_t, string]

    # FHE backend
    cdef enum class backend_t(uint8_t):
        none,
        seal,
        palisade
    cdef cpp_map backend_t_str[backend_t, string]

    # ============================== Classes ===================================
    # Ciphertext
    cdef cppclass AfCtxt:
        pass

    # Plaintext
    cdef cppclass AfPtxt:
        pass

    # Polynomials
    cdef cppclass AfPoly:
        AfPoly() except +
        void add_inplace(const AfPoly &other) except +
        void subtract_inplace(const AfPoly &other) except +
        void multiply_inplace(const AfPoly &other) except +
        bool invert_inplace() except +

    # Afhel
    cdef cppclass Afhel:
        # ----------------------- OBJECT MANAGEMENT ----------------------------
        Afhel() except +

        # -------------------------- CRYPTOGRAPHY ------------------------------
        # CONTEXT & KEY GENERATION
        void ContextGen(scheme_t scheme, size_t poly_modulus_degree, 
                        uint64_t plain_modulus_bit_size, uint64_t plain_modulus,
                        int sec, vector[int] qs) except +
        void KeyGen() except +
        void relinKeyGen() except +
        void rotateKeyGen() except +

        # ENCRYPTION
        void encrypt(AfPtxt& ptxt, AfCtxt& ctxtOut) except +
        void encrypt_v(vector[AfPtxt]& plainV, vector[AfCtxt]& ctxtVOut) except +
        
        # DECRYPTION
        void decrypt(AfCtxt &ctxtInOut, AfPtxt &plainOut) except +
        void decrypt_v(vector[AfCtxt] &ctxtV, vector[AfPtxt] &plainVOut) except +
        
        # NOISE LEVEL
        int noise_level(AfCtxt& ctxtInOut) except +

        # ------------------------------ CODEC ---------------------------------
        # ENCODE
        # bfv
        void encode_i(vector[int64_t] &values, AfPtxt &plainOut) except +
        # ckks
        void encode_f(vector[double] &values, double scale, AfPtxt &plainVOut) except +
        void encode_c(vector[cy_complex] &values, double scale, AfPtxt &plainVOut) except +
        
        # DECODE
        # bfv
        void decode_i(AfPtxt &ptxt, vector[int64_t] &valueVOut) except +
        # ckks
        void decode_f(AfPtxt &ptxt, vector[double] &valueVOut) except +
        void decode_c(AfPtxt &ptxt, vector[cy_complex] &valueVOut) except +

        # AUXILIARY
        void data(AfPtxt &ptxt, uint64_t *dest) except +
        void allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest) except +
        
        # -------------------------- RELINEARIZATION ---------------------------
        void relinearize(AfCtxt& ctxtInOut) except +

        # ---------------------- HOMOMORPHIC OPERATIONS ------------------------
        # Negate
        void negate(AfCtxt& ctxtInOut) except +
        void negate_v(vector[AfCtxt]& ctxtV) except +
        # Square
        void square(AfCtxt& ctxtInOut) except +
        void square_v(vector[AfCtxt]& ctxtV) except +
        # Add
        void add(AfCtxt& ctxtInOut, AfCtxt& ctxt) except +
        void add_plain(AfCtxt& ctxtInOut, AfPtxt& plain2) except +
        void add_v(vector[AfCtxt]& ctxtVInOut, vector[AfCtxt]& ctxtV) except +
        void add_plain_v(vector[AfCtxt]& ctxtVInOut, vector[AfPtxt]& ptxtV) except +
        void cumsum_v(vector[AfCtxt]& ctxtV, AfCtxt& ctxtOut) except +

        # Subtract
        void sub(AfCtxt& ctxtInOut, AfCtxt& ctxt) except +
        void sub_plain(AfCtxt& ctxtInOut, AfPtxt& plain2) except +
        void sub_v(vector[AfCtxt]& ctxtVInOut, vector[AfCtxt]& ctxtV) except +
        void sub_plain_v(vector[AfCtxt]& ctxtVInOut, vector[AfPtxt]& ptxtV) except +

        # Multiply
        void multiply(AfCtxt& ctxtInOut, AfCtxt& ctxt) except +
        void multiply_plain(AfCtxt& ctxtInOut, AfPtxt& ptxt) except +
        void multiply_v(vector[AfCtxt]& ctxtVInOut, vector[AfCtxt]& ctxtV) except +
        void multiply_plain_v(vector[AfCtxt]& ctxtVInOut, vector[AfPtxt]& ptxtV) except + 

        # Rotate
        void rotate(AfCtxt& ctxtInOut, int& k) except +
        void rotate_v(vector[AfCtxt]& ctxtV, int& k) except +

        # Power
        void exponentiate(AfCtxt& ctxtInOut, uint64_t& expon) except +
        void exponentiate_v(vector[AfCtxt]& ctxtV, uint64_t& expon) except +

        # ckks -> rescale and mod switching
        void rescale_to_next(AfCtxt &ctxtInOut) except +
        void rescale_to_next_v(vector[AfCtxt]& ctxtVInOut) except +
        void mod_switch_to_next(AfCtxt &ctxtInOut) except +
        void mod_switch_to_next_v(vector[AfCtxt]& ctxtVInOut) except +
        void mod_switch_to_next_plain(AfPtxt &ptxtInOut) except +
        void mod_switch_to_next_plain_v(vector[AfPtxt]& ptxtVInOut) except +

        # -------------------------------- I/O --------------------------------
        # SAVE/LOAD CONTEXT
        size_t save_context(ostream &out_stream, string &compr_mode) except +
        size_t load_context(istream &in_stream) except +

        # SAVE/LOAD PUBLICKEY
        size_t save_public_key(ostream &out_stream, string &compr_mode) except +
        size_t load_public_key(istream &in_stream) except +

        # SAVE/LOAD SECRETKEY
        size_t save_secret_key(ostream &out_stream, string &compr_mode) except +
        size_t load_secret_key(istream &in_stream) except +

        # SAVE/LOAD RELINKEY
        size_t save_relin_keys(ostream &out_stream, string &compr_mode) except +
        size_t load_relin_keys(istream &in_stream) except +

        # SAVE/LOAD ROTKEYS
        size_t save_rotate_keys(ostream &out_stream, string &compr_mode) except +
        size_t load_rotate_keys(istream &in_stream) except +

        # SAVE/LOAD PLAINTEXT --> Could be achieved outside of Afseal
        size_t save_plaintext(ostream &out_stream, string &compr_mode, AfPtxt &plain) except +
        size_t load_plaintext(istream &in_stream, AfPtxt &plain) except +

        # SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afseal
        size_t save_ciphertext(ostream &out_stream, string &compr_mode, AfCtxt &ciphert) except +
        size_t load_ciphertext(istream &in_stream, AfCtxt &plain) except +

        # ----------------------------- AUXILIARY -----------------------------
        long maxBitCount(long poly_modulus_degree, int sec_level) except +

        # ckks
        double scale(AfCtxt &ctxt) except +
        void override_scale(AfCtxt &ctxt, double scale) except +

        # GETTERS
        bool batchEnabled() except +
        size_t get_nSlots() except +
        int get_nRots() except +
        uint64_t get_plain_modulus() except +
        size_t get_poly_modulus_degree() except +
        scheme_t get_scheme() except +
        int get_sec() except +
        int total_coeff_modulus_bit_count() except +

        bool is_secretKey_empty() except+
        bool is_publicKey_empty() except+
        bool is_rotKey_empty() except+
        bool is_relinKeys_empty() except+
        bool is_context_empty() except+

        # POLY
        # inplace ops -> result in first operand
        void add_inplace(AfPoly &p1, AfPoly &p2) except+
        void subtract_inplace(AfPoly &p1, AfPoly &p2) except+
        void multiply_inplace(AfPoly &p1, AfPoly &p2) except+
        bool invert_inplace(AfPoly &p) except+

        # I/O
        void poly_to_ciphertext(AfPoly &p, AfCtxt &ctxt, size_t i) except+
        void poly_to_plaintext(AfPoly &p, AfPtxt &ptxt) except+



#===============================================================================
#========================= AFSEAL - C++ Interface ==============================
#===============================================================================
cdef extern from "Afseal.h" nogil:
    cdef cppclass AfsealCtxt(AfCtxt, Ciphertext):
        AfsealCtxt() except +
        AfsealCtxt(const AfsealCtxt &other) except +
        void set_scale(double new_scale)

    cdef cppclass AfsealPtxt(AfPtxt, Plaintext):
        AfsealPtxt() except +
        AfsealPtxt(const AfsealPtxt &other) except +
        void set_scale(double new_scale)

    cdef cppclass Afseal(Afhel):
        Afseal() except +
        Afseal(const Afseal &other) except +
        AfsealPoly get_publicKey_poly(size_t index) except +
        AfsealPoly get_secretKey_poly() except +

    cdef cppclass AfsealPoly(AfPoly):
        AfsealPoly(Afseal &afseal, const AfsealCtxt &ref) except+
        AfsealPoly(AfsealPoly &other) except+
        AfsealPoly(Afseal &afseal, AfsealCtxt &ctxt, size_t index) except+
        AfsealPoly(Afseal &afseal, AfsealPtxt &ptxt, const AfsealCtxt &ref) except+

        vector[cy_complex] to_coeff_list(Afseal &afseal) except+

        cy_complex get_coeff(Afseal &afseal, size_t i) except+
        void set_coeff(Afseal &afseal, cy_complex &val, size_t i) except+
        size_t get_coeff_count() except+
        size_t get_coeff_modulus_count() except+