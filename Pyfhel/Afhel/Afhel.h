#ifndef AFHEL_H
#define AFHEL_H


#include <iostream>  /* Print in std::cout */
#include <string>    /* std::string class */
#include <vector>    /* Vectorizing all operations */
#include <thread>    /* memory pools, multithread*/
#include <memory>    /* Smart Pointers*/
#include <complex>   /* Complex Numbers */
#include <map>          /* map */

// Forward Declarations
class AfPoly;
class AfCtxt;
class AfPtxt;
class Afhel;

//----------------------------- FHE scheme type --------------------------------
enum class scheme_t : std::uint8_t{
  // No scheme set; cannot be used for encryption
  none = 0x0,
  // Brakerski/Fan-Vercauteren scheme
  bfv = 0x1,
  // Cheon-Kim-Kim-Song scheme
  ckks = 0x2
};

static std::map<scheme_t, std::string> scheme_t_str {
   {scheme_t::none, "none"},
   {scheme_t::bfv,  "bfv"},
   {scheme_t::ckks, "ckks"},
};
static std::map<std::string, scheme_t> scheme_t_map {
   {"none", scheme_t::none},
   {"bfv",  scheme_t::bfv},
   {"ckks", scheme_t::ckks},
};

//------------------------------- FHE backend ----------------------------------
enum class backend_t : std::uint8_t{
  // No backend set; cannot be used
  none = 0xA,
  // SEAL - Microsoft Research (default)
  seal = 0xB,
  // PALISADE
  palisade = 0xC
};
static std::map<backend_t, std::string> backend_t_str {
   {backend_t::none, "none"},
   {backend_t::seal,  "seal"},
   {backend_t::palisade, "palisade"},
};
static std::map<std::string, backend_t> backend_t_map {
   {"none", backend_t::none},
   {"seal",  backend_t::seal},
   {"palisade", backend_t::palisade},
};


// =============================================================================
// ================== ABSTRACTION FOR HOMOMORPHIC ENCR. LIBS ===================
// =============================================================================
class Afhel {
 public:
  // FHE backend
  backend_t backend;

  // --------------------------- CLASS MANAGEMENT ------------------------------
  virtual ~Afhel(){};

  // ----------------------------- CRYPTOGRAPHY --------------------------------
  // CONTEXT GENERATION
  virtual void ContextGen(
    scheme_t scheme, uint64_t poly_modulus_degree, uint64_t plain_modulus_bit_size, uint64_t plain_modulus, 
    int sec, std::vector<int> qs = {}) = 0;

  // KEY GENERATION
  virtual void KeyGen() = 0;
  virtual void relinKeyGen() = 0;
  virtual void rotateKeyGen() = 0;

  // ENCRYPTION
  virtual void encrypt(AfPtxt &plain1, AfCtxt &cipherOut) = 0;
  virtual void encrypt_v(std::vector<AfPtxt*> &plainV, std::vector<AfCtxt*> &cipherVOut) = 0;

  // DECRYPTION
  virtual void decrypt(AfCtxt &cipher1, AfPtxt &plainOut) = 0;
  virtual void decrypt_v(std::vector<AfCtxt*> &cipherV, std::vector<AfPtxt*> &plainVOut) = 0;

  // NOISE MEASUREMENT
  virtual int noise_level(AfCtxt &cipher1) = 0;

  // ------------------------------ CODEC -------------------------------
  // ENCODE
  // bfv
  virtual void encode_i(std::vector<int64_t> &values, AfPtxt &plainOut) = 0;
  // ckks
  virtual void encode_f(std::vector<double> &values, double scale, AfPtxt &plainVOut) = 0;
  virtual void encode_c(std::vector<std::complex<double>> &values, double scale, AfPtxt &plainVOut) = 0;

  // DECODE
  // bfv
  virtual void decode_i(AfPtxt &plain1, std::vector<int64_t> &valueVOut) = 0;
  // ckks
  virtual void decode_f(AfPtxt &plain1, std::vector<double> &valueVOut) = 0;
  virtual void decode_c(AfPtxt &plain1, std::vector<std::complex<double>> &valueVOut) = 0;
  
  // -------------------------- RELINEARIZATION -------------------------
  virtual void relinearize(AfCtxt &cipher1) = 0;

  // ---------------------- HOMOMORPHIC OPERATIONS ----------------------
  // NEGATE
  virtual void negate(AfCtxt &cipher1) = 0;
  virtual void negate_v(std::vector<AfCtxt*> &cipherV) = 0;

  // SQUARE
  virtual void square(AfCtxt &cipher1) = 0;
  virtual void square_v(std::vector<AfCtxt*> &cipherV) = 0;

  // ADDITION
  virtual void add(AfCtxt &cipherInOut, AfCtxt &cipher2) = 0;
  virtual void add_plain(AfCtxt &cipherInOut, AfPtxt &plain2) = 0;
  virtual void add_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfCtxt*> &cipherV2) = 0;
  virtual void add_plain_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfPtxt*> &plainV2) = 0;

  // SUBTRACTION
  virtual void sub(AfCtxt &cipherInOut, AfCtxt &cipher2) = 0;
  virtual void sub_plain(AfCtxt &cipherInOut, AfPtxt &plain2) = 0;
  virtual void sub_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfCtxt*> &cipherV2) = 0;
  virtual void sub_plain_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfPtxt*> &plainV2) = 0;


  // MULTIPLICATION
  virtual void multiply(AfCtxt &cipherVInOut, AfCtxt &cipher2) = 0;
  virtual void multiply_plain(AfCtxt &cipherVInOut, AfPtxt &plain1) = 0;
  virtual void multiply_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfCtxt*> &cipherV2) = 0;
  virtual void multiply_plain_v(std::vector<AfCtxt*> &cipherVInOut, std::vector<AfPtxt*> &plainV2) = 0;

  // ROTATE
  virtual void rotate(AfCtxt &cipher1, int &k) = 0;
  virtual void rotate_v(std::vector<AfCtxt*> &cipherV, int &k) = 0;

  // POWER
  virtual void exponentiate(AfCtxt &cipher1, uint64_t &expon) = 0;
  virtual void exponentiate_v(std::vector<AfCtxt*> &cipherV, uint64_t &expon) = 0;

  // CKKS -> Rescaling and mod switching
  virtual void rescale_to_next(AfCtxt &cipher1) = 0;
  virtual void mod_switch_to_next(AfCtxt &cipher1) = 0;
  virtual void mod_switch_to_next_plain(AfPtxt &ptxt) = 0;


  // -------------------------------- I/O -------------------------------
  // SAVE/LOAD CONTEXT
  virtual size_t save_context(std::ostream &out_stream, std::string &compr_mode) = 0;
  virtual size_t load_context(std::istream &in_stream) = 0;

  // SAVE/LOAD PUBLICKEY
  virtual size_t save_public_key(std::ostream &out_stream, std::string &compr_mode) = 0;
  virtual size_t load_public_key(std::istream &in_stream) = 0;

  // SAVE/LOAD SECRETKEY
  virtual size_t save_secret_key(std::ostream &out_stream, std::string &compr_mode) = 0;
  virtual size_t load_secret_key(std::istream &in_stream) = 0;

  // SAVE/LOAD RELINKEY
  virtual size_t save_relin_keys(std::ostream &out_stream, std::string &compr_mode) = 0;
  virtual size_t load_relin_keys(std::istream &in_stream) = 0;

  // SAVE/LOAD ROTKEYS
  virtual size_t save_rotate_keys(std::ostream &out_stream, std::string &compr_mode) = 0;
  virtual size_t load_rotate_keys(std::istream &in_stream) = 0;

  // SAVE/LOAD PLAINTEXT --> Could be achieved outside of Afhel
  virtual size_t save_plaintext(std::ostream &out_stream, std::string &compr_mode, AfPtxt &plain) = 0;
  virtual size_t load_plaintext(std::istream &in_stream, AfPtxt &plain) = 0;

  // SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afhel
  virtual size_t save_ciphertext(std::ostream &out_stream, std::string &compr_mode, AfCtxt &ciphert) = 0;
  virtual size_t load_ciphertext(std::istream &in_stream, AfCtxt &plain) = 0;

  // ----------------------------- AUXILIARY ----------------------------
  // GETTERS
  virtual uint64_t get_plain_modulus() = 0;
  virtual size_t get_poly_modulus_degree() = 0;
  virtual scheme_t get_scheme() = 0;


  // ------------------------------- AFPOLY -----------------------------
  friend class AfPoly;

  // POLY OPS
  virtual void add_inplace(AfPoly &p1, AfPoly &p2) = 0;
  virtual void subtract_inplace(AfPoly &p1, AfPoly &p2) = 0;
  virtual void multiply_inplace(AfPoly &p1, AfPoly &p2) = 0;
  virtual void invert_inplace(AfPoly &p) = 0;

  // I/O
  virtual void poly_to_ciphertext(AfPoly &p, AfCtxt &ctxt, size_t i) = 0;
  virtual void poly_to_plaintext(AfPoly &p, AfPtxt &ptxt) = 0;

  // Coefficient Access
  virtual std::complex<double> get_coeff(AfPoly& poly, size_t i) = 0;
  virtual void set_coeff(AfPoly& poly, std::complex<double> &val, size_t i) = 0;
  virtual std::vector<std::complex<double>> to_coeff_list(AfPoly& poly) = 0;
};



// =============================================================================
// ======================= ABSTRACTION FOR PLAINTEXTS ==========================
// =============================================================================
class AfPtxt{
 public:
  virtual ~AfPtxt(){};
};


// =============================================================================
// ====================== ABSTRACTION FOR CIPHERTEXTS ==========================
// =============================================================================
class AfCtxt{
 public:
  virtual ~AfCtxt(){};
};


// =============================================================================
// ====================== ABSTRACTION FOR POLYNOMIALS ==========================
// =============================================================================
// Wrapper for underlying polynomials that make up plaintexts, ciphertexts, etc.
class AfPoly {
 public:
  virtual ~AfPoly(){};

  // ----------- COEFF ACCESSORS ------------
  virtual std::vector<std::complex<double>> to_coeff_list(Afhel &afhel) = 0;
  virtual std::complex<double> get_coeff(Afhel &afhel, size_t i) = 0;
  virtual void set_coeff(Afhel &afhel, std::complex<double> &val, size_t i) = 0;

  // -------------- OPERATIONS --------------
  //inplace ops -> result in first operand
  virtual void add_inplace(const AfPoly &other) = 0;
  virtual void subtract_inplace(const AfPoly &other) = 0;
  virtual void multiply_inplace(const AfPoly &other) = 0;
  virtual bool invert_inplace() = 0;
};


// Include all backends
#include "Afseal.h"

#endif /*AFHEL_H*/
