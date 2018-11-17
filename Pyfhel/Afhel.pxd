# distutils: language = c++
# distutils: sources = ../SEAL/SEAL/seal/plaintext.cpp ../SEAL/SEAL/seal/ciphertext.cpp ../Afhel/Afseal.cpp
#cython: language_level=3, boundscheck=False

# -------------------------------- IMPORTS ------------------------------------
# Import from Cython libs required C/C++ types for the Afhel API
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdint cimport int64_t
from libc.stdint cimport uint64_t
        
# Import our own wrapper for iostream classes, used for I/O ops
from Pyfhel.iostream cimport istream, ostream, ifstream, ofstream       


# --------------------------- EXTERN DECLARATION ------------------------------
# SEAL plaintext class        
cdef extern from "SEAL/SEAL/seal/plaintext.h" namespace "seal" nogil:
    cdef cppclass Plaintext:
        Plaintext() except +
        Plaintext(const Plaintext &copy) except +
        bool is_zero() except +
        string to_string() except +
        void save(ostream &stream) except +
        void load(istream &stream) except +
        
# SEAL ciphertext class        
cdef extern from "SEAL/SEAL/seal/ciphertext.h" namespace "seal" nogil:
    cdef cppclass Ciphertext:
        Ciphertext() except +
        Ciphertext(const Ciphertext &copy) except +
        int size_capacity() except +
        int size() except +
        void save(ostream &stream) except +
        void load(istream &stream) except +

# Afseal class to abstract SEAL
cdef extern from "Afhel/Afseal.h" nogil:
    cdef cppclass Afseal:
        # ----------------------- OBJECT MANAGEMENT ---------------------------
        Afseal() except +
        Afseal(const Afseal &otherAfseal) except +
        Afseal(Afseal &&source) except +

        # -------------------------- CRYPTOGRAPHY -----------------------------
        # CONTEXT & KEY GENERATION
        void ContextGen(long p, long m, bool flagBatching, long base,
                 long sec, int intDigits, int fracDigits) except +
        void KeyGen() except +

        # ENCRYPTION
        Ciphertext encrypt(Plaintext& plain1) except +
        Ciphertext encrypt(double& value1) except +
        Ciphertext encrypt(int64_t& value1) except +
        Ciphertext encrypt(vector[int64_t]& valueV) except +
        vector[Ciphertext] encrypt(vector[int64_t]& valueV, bool& dummy_NoBatch) except +
        vector[Ciphertext] encrypt(vector[double]& valueV) except +
        
        void encrypt(Plaintext& plain1, Ciphertext& cipherOut) except +
        void encrypt(double& value1, Ciphertext& cipherOut) except +
        void encrypt(int64_t& value1, Ciphertext& cipherOut) except +
        void encrypt(vector[int64_t]& valueV, Ciphertext& cipherOut) except +
        void encrypt(vector[int64_t]& valueV, vector[Ciphertext]& cipherOut) except +
        void encrypt(vector[double]& valueV, vector[Ciphertext]& cipherOut) except +

        # DECRYPTION
        vector[int64_t] decrypt(Ciphertext& cipher1) except +

        void decrypt(Ciphertext& cipher1, Plaintext& plainOut) except +
        void decrypt(Ciphertext& cipher1, int64_t& valueOut) except + 
        void decrypt(Ciphertext& cipher1, double& valueOut) except +
        void decrypt(Ciphertext& cipher1, vector[int64_t]& valueVOut) except + 
        void decrypt(vector[Ciphertext]& cipherV, vector[int64_t]& valueVOut) except +
        void decrypt(vector[Ciphertext]& cipherV, vector[double]& valueVOut) except +

        # NOISE LEVEL
        int noiseLevel(Ciphertext& cipher1) except +

        # ------------------------------ CODEC --------------------------------
        # ENCODE
        Plaintext encode(int64_t& value1) except +
        Plaintext encode(double& value1) except +
        Plaintext encode(vector[int64_t] &values) except +
        vector[Plaintext] encode(vector[int64_t] &values, bool dummy_NoBatch) except +
        vector[Plaintext] encode(vector[double] &values) except +

        void encode(int64_t& value1, Plaintext& plainOut) except +
        void encode(double& value1, Plaintext& plainOut) except +
        void encode(vector[int64_t] &values, Plaintext& plainOut) except +
        void encode(vector[int64_t] &values, vector[Plaintext]& plainVOut) except +
        void encode(vector[double] &values, vector[Plaintext]& plainVOut) except +
        
        # DECODE 
        vector[int64_t] decode(Plaintext& plain1) except +
        
        void decode(Plaintext& plain1, double& valOut) except +
        void decode(Plaintext& plain1, vector[int64_t] &valueVOut) except +
        void decode(vector[Plaintext]& plain1, vector[int64_t] &valueVOut) except +
        void decode(vector[Plaintext]& plain1, vector[double] &valueVOut) except +

        # -------------------------- OTHER OPERATIONS -------------------------
        void rotateKeyGen(int& bitCount) except +
        void relinKeyGen(int& bitCount, int& size) except +
        void relinearize(Ciphertext& cipher1) except +

        # ---------------------- HOMOMORPHIC OPERATIONS -----------------------
        void square(Ciphertext& cipher1) except +
        void square(vector[Ciphertext]& cipherV) except +
        void negate(Ciphertext& cipher1) except +
        void negate(vector[Ciphertext]& cipherV) except +
        void add(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void add(Ciphertext& cipher1, Plaintext& plain2) except +
        void add(vector[Ciphertext]& cipherV, Ciphertext& cipherOut) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void add(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void sub(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void sub(Ciphertext& cipher1, Plaintext& plain2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void sub(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void multiply(Ciphertext& cipher1, Ciphertext& cipher2) except +
        void multiply(Ciphertext& cipher1, Plaintext& plain1) except +
        void multiply(vector[Ciphertext]& cipherV1, Ciphertext& cipherOut) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Ciphertext]& cipherV2) except +
        void multiply(vector[Ciphertext]& cipherVInOut, vector[Plaintext]& plainV2) except +
        void rotate(Ciphertext& cipher1, int& k) except +
        void rotate(vector[Ciphertext]& cipherV, int& k) except +
        void exponentiate(Ciphertext& cipher1, uint64_t& expon) except +
        void exponentiate(vector[Ciphertext]& cipherV, uint64_t& expon) except +
        void polyEval(Ciphertext& cipher1, vector[int64_t]& coeffPoly) except +
        void polyEval(Ciphertext& cipher1, vector[double]& coeffPoly) except +

        # -------------------------------- I/O --------------------------------
        bool saveContext(string fileName) except +
        bool restoreContext(string fileName) except +
        
        bool savepublicKey(string fileName) except +
        bool restorepublicKey(string fileName) except +
        
        bool savesecretKey(string fileName) except +
        bool restoresecretKey(string fileName) except +
        
        bool saverelinKey(string fileName) except +
        bool restorerelinKey(string fileName) except +
        
        bool saverotateKey(string fileName) except +
        bool restorerotateKey(string fileName) except +

        # ----------------------------- AUXILIARY -----------------------------
        bool batchEnabled() except +
        long relinBitCount() except +

        # GETTERS
        int getnSlots() except +
        int getp() except +
        int getm() except +
        int getbase() except +
        int getsec() except + 
        int getintDigits() except +
        int getfracDigits() except +
        bool getflagBatch() except +
