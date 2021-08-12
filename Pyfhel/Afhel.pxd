# distutils: language = c++
# distutils: sources = ../SEAL/SEAL/seal/plaintext.cpp ../SEAL/SEAL/seal/ciphertext.cpp ../Afhel/Afseal.cpp
#cython: language_level=3, boundscheck=False

# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp.complex cimport complex as c_complex
from libcpp cimport bool
from numpy cimport int64_t, uint64_t
        
# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream       

ctypedef c_complex[double] cy_complex

# --------------------------- EXTERN DECLARATION ------------------------------
# SEAL plaintext class        
cdef extern from "seal/plaintext.h" namespace "seal" nogil:
    cdef cppclass Plaintext:
        Plaintext() except +
        Plaintext(const Plaintext &copy) except +
        bool is_zero() except +
        string to_string() except +
        
# SEAL ciphertext class        
cdef extern from "seal/ciphertext.h" namespace "seal" nogil:
    cdef cppclass Ciphertext:
        Ciphertext() except +
        Ciphertext(const Ciphertext &copy) except +
        int size_capacity() except +
        int size() except +


# Afhel class
cdef extern from "Afhel/afhel.h" nogil:
    cdef cppclass AfCtxt:
        AfCtxt() except +

    cdef cppclass AfPtxt:
        AfPtxt() except +

    cdef cppclass AfPoly:
        AfPoly() except +
        void add_inplace(const AfPoly &other) except +
        void subtract_inplace(const AfPoly &other) except +
        void multiply_inplace(const AfPoly &other) except +
        bool invert_inplace() except +

    cdef cppclass Afhel:
        # ----------------------- OBJECT MANAGEMENT ----------------------------
        Afhel() except +

        # -------------------------- CRYPTOGRAPHY ------------------------------
        # CONTEXT & KEY GENERATION
        void ContextGen(string scheme_t, uint64_t plain_modulus, size_t poly_modulus_degree, long sec, vector[int] qs) except +
        void KeyGen() except +
        void relinKeyGen() except +
        void rotateKeyGen() except +

        # ENCRYPTION
        void encrypt(AfPtxt& plain1, AfCtxt& cipherOut) except +
        void encrypt(vector[AfPtxt]& plainV, vector[AfCtxt]& cipherVOut) except +
        
        # DECRYPTION
        void decrypt(AfCtxt &cipher1, AfPtxt &plainOut) except +
        void decrypt(vector[AfCtxt] &cipherV, vector[AfPtxt] &plainVOut) except +
        
        # NOISE LEVEL
        int noise_level(AfCtxt& cipher1) except +

        # ------------------------------ CODEC ---------------------------------
        # ENCODE
        # bfv
        void encode(vector[int64_t] &values, AfPtxt &plainOut) except +
        # ckks
        void encode(vector[double] &values, double scale, AfPtxt &plainVOut);
        void encode(vector[cy_complex] &values, double scale, AfPtxt &plainVOut);
        
        # DECODE
        # bfv
        void decode(AfPtxt &plain1, vector[int64_t] &valueVOut) except +
        # ckks
        void decode(AfPtxt &plain1, vector[double] &valueVOut) except +
        void decode(AfPtxt &plain1, vector[cy_complex] &valueVOut) except +

        # AUXILIARY
        void data(AfPtxt &ptxt, uint64_t *dest) except +
        void allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest) except +
        
        # -------------------------- RELINEARIZATION ---------------------------
        void relinearize(AfCtxt& cipher1) except +

        # ---------------------- HOMOMORPHIC OPERATIONS ------------------------
        # Negate
        void negate(AfCtxt& cipher1) except +
        void negate(vector[AfCtxt]& cipherV) except +
        # Square
        void square(AfCtxt& cipher1) except +
        void square(vector[AfCtxt]& cipherV) except +
        # Add
        void add(AfCtxt& cipher1, AfCtxt& cipher2) except +
        void add(AfCtxt& cipher1, AfPtxt& plain2) except +
        void add(vector[AfCtxt]& cipherVInOut, vector[AfCtxt]& cipherV2) except +
        void add(vector[AfCtxt]& cipherVInOut, vector[AfPtxt]& plainV2) except +
        void cumsum(vector[AfCtxt]& cipherV, AfCtxt& cipherOut) except +

        # Subtract
        void sub(AfCtxt& cipher1, AfCtxt& cipher2) except +
        void sub(AfCtxt& cipher1, AfPtxt& plain2) except +
        void sub(vector[AfCtxt]& cipherVInOut, vector[AfCtxt]& cipherV2) except +
        void sub(vector[AfCtxt]& cipherVInOut, vector[AfPtxt]& plainV2) except +

        # Multiply
        void multiply(AfCtxt& cipher1, AfCtxt& cipher2) except +
        void multiply(AfCtxt& cipher1, AfPtxt& plain1) except +
        void multiply(vector[AfCtxt]& cipherVInOut, vector[AfCtxt]& cipherV2) except +
        void multiply(vector[AfCtxt]& cipherVInOut, vector[AfPtxt]& plainV2) except +        
        void cumprod(vector[AfCtxt]& cipherV1, AfCtxt& cipherOut) except +

        # Rotate
        void rotate(AfCtxt& cipher1, int& k) except +
        void rotate(vector[AfCtxt]& cipherV, int& k) except +

        # Power
        void exponentiate(AfCtxt& cipher1, uint64_t& expon) except +
        void exponentiate(vector[AfCtxt]& cipherV, uint64_t& expon) except +

        # ckks -> rescale and mod switching
        void rescale_to_next(AfCtxt &cipher1) except +
        void mod_switch_to_next(AfCtxt &cipher1) except +
        void mod_switch_to_next(AfPtxt &ptxt) except +

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
        int get_nSlots() except +
        int get_sec() except +
        uint64_t get_plain_modulus() except +
        size_t get_poly_modulus_degree() except +
        string get_scheme() except +

        bool is_secretKey_empty() except+
        bool is_publicKey_empty() except+
        bool is_rotKey_empty() except+
        bool is_relinKey_empty() except+
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

    # Afseal class to abstract internal polynoms
    cdef cppclass AfPoly:
        AfPoly(Afseal &afseal, const Ciphertext &ref) except+
        AfPoly(AfPoly &other) except+
        AfPoly(Afseal &afseal, Ciphertext &ctxt, size_t index) except+
        AfPoly(Afseal &afseal, Plaintext &ptxt, const Ciphertext &ref) except+

        vector[cy_complex] to_coeff_list(Afseal &afseal) except+

        cy_complex get_coeff(Afseal &afseal, size_t i) except+
        void set_coeff(Afseal &afseal, cy_complex &val, size_t i) except+
        size_t get_coeff_count() except+
        size_t get_coeff_modulus_count() except+

# Afseal class to abstract SEAL
cdef extern from "Afhel/Afseal.h" nogil:
    cdef cppclass Afseal:
        # ----------------------- OBJECT MANAGEMENT ----------------------------
        Afseal() except +
        Afseal(const Afseal &otherAfseal) except +

        # -------------------------- CRYPTOGRAPHY ------------------------------
        # CONTEXT & KEY GENERATION
        void ContextGen(string scheme_t, uint64_t plain_modulus, size_t poly_modulus_degree, long sec, vector[int] qs) except +
        void KeyGen() except +
        void relinKeyGen() except +
        void rotateKeyGen() except +

        # ENCRYPTION
        void encrypt(Plaintext& plain1, Ciphertext& cipherOut) except +
        void encrypt(vector[Plaintext]& plainV, vector[Ciphertext]& cipherVOut) except +
        
        # DECRYPTION
        void decrypt(Ciphertext &cipher1, Plaintext &plainOut) except +
        void decrypt(vector[Ciphertext] &cipherV, vector[Plaintext] &plainVOut) except +
        
        # NOISE LEVEL
        int noise_level(Ciphertext& cipher1) except +

        # ------------------------------ CODEC ---------------------------------
        # ENCODE
        # bfv
        void encode(vector[int64_t] &values, Plaintext &plainOut) except +
        # ckks
        void encode(vector[double] &values, double scale, Plaintext &plainVOut);
        void encode(vector[cy_complex] &values, double scale, Plaintext &plainVOut);
        
        # DECODE
        # bfv
        void decode(Plaintext &plain1, vector[int64_t] &valueVOut) except +
        # ckks
        void decode(Plaintext &plain1, vector[double] &valueVOut) except +
        void decode(Plaintext &plain1, vector[cy_complex] &valueVOut) except +

        # AUXILIARY
        void data(Plaintext &ptxt, uint64_t *dest) except +
        void allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest) except +
        
        # -------------------------- RELINEARIZATION ---------------------------
        void relinearize(Ciphertext& cipher1) except +

        # ---------------------- HOMOMORPHIC OPERATIONS ------------------------
        # Negate
        void negate(Ciphertext& cipher1) except +
        void negate(vector[Ciphertext]& cipherV) except +
        # Square
        void square(Ciphertext& cipher1) except +
        void square(vector[Ciphertext]& cipherV) except +
        # Add
        void add(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void add(Ciphertext& cipher1, Plaintext& plain2) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void cumsum(vector[Ciphertext]& cipherV, Ciphertext& cipherOut) except +

        # Subtract
        void sub(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void sub(Ciphertext& cipher1, Plaintext& plain2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +

        # Multiply
        void multiply(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void multiply(Ciphertext& cipher1, Plaintext& plain1) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +        
        void cumprod(vector[Ciphertext]& cipherV1, Ciphertext& cipherOut) except +

        # Rotate
        void rotate(Ciphertext& cipher1, int& k) except +
        void rotate(vector[Ciphertext]& cipherV, int& k) except +

        # Power
        void exponentiate(Ciphertext& cipher1, uint64_t& expon) except +
        void exponentiate(vector[Ciphertext]& cipherV, uint64_t& expon) except +

        # ckks -> rescale and mod switching
        void rescale_to_next(Ciphertext &cipher1) except +
        void mod_switch_to_next(Ciphertext &cipher1) except +
        void mod_switch_to_next(Plaintext &ptxt) except +

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
        size_t save_plaintext(ostream &out_stream, string &compr_mode, Plaintext &plain) except +
        size_t load_plaintext(istream &in_stream, Plaintext &plain) except +

        # SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afseal
        size_t save_ciphertext(ostream &out_stream, string &compr_mode, Ciphertext &ciphert) except +
        size_t load_ciphertext(istream &in_stream, Ciphertext &plain) except +

        # ----------------------------- AUXILIARY -----------------------------
        long maxBitCount(long poly_modulus_degree, int sec_level) except +

        # ckks
        double scale(Ciphertext &ctxt) except +
        void override_scale(Ciphertext &ctxt, double scale) except +

        # GETTERS
        bool batchEnabled() except +
        int get_nSlots() except +
        int get_sec() except +
        uint64_t get_plain_modulus() except +
        size_t get_poly_modulus_degree() except +
        string get_scheme() except +

        bool is_secretKey_empty() except+
        bool is_publicKey_empty() except+
        bool is_rotKey_empty() except+
        bool is_relinKey_empty() except+
        bool is_context_empty() except+

        # POLY
        # inplace ops -> result in first operand
        void add_inplace(AfsealPoly &p1, AfsealPoly &p2) except+
        void subtract_inplace(AfsealPoly &p1, AfsealPoly &p2) except+
        void multiply_inplace(AfsealPoly &p1, AfsealPoly &p2) except+
        bool invert_inplace(AfsealPoly &p) except+

        # I/O
        void poly_to_ciphertext(AfsealPoly &p, Ciphertext &ctxt, size_t i) except+
        void poly_to_plaintext(AfsealPoly &p, Plaintext &ptxt) except+

    # Afseal class to abstract internal polynoms
    cdef cppclass AfsealPoly:
        AfsealPoly(Afseal &afseal, const Ciphertext &ref) except+
        AfsealPoly(AfsealPoly &other) except+
        AfsealPoly(Afseal &afseal, Ciphertext &ctxt, size_t index) except+
        AfsealPoly(Afseal &afseal, Plaintext &ptxt, const Ciphertext &ref) except+

        vector[cy_complex] to_coeff_list(Afseal &afseal) except+

        cy_complex get_coeff(Afseal &afseal, size_t i) except+
        void set_coeff(Afseal &afseal, cy_complex &val, size_t i) except+
        size_t get_coeff_count() except+
        size_t get_coeff_modulus_count() except+