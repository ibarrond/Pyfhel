/**
 * @file Afseal.h
 *  --------------------------------------------------------------------
 * @brief Header of Afseal, library that creates an abstraction over basic
 *  functionalities of SEAL as a Homomorphic Encryption library, such as
 *  addition, multiplication, scalar product and others.
 *
 *  --------------------------------------------------------------------
 * @author Alberto Ibarrondo (ibarrond)
 *  --------------------------------------------------------------------
 * @bugs No known bugs
 */

/*  License: Apache-2.0
 *
 *  Pyfhel is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Pyfhel is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */


#ifndef AFSEAL_H
#define AFSEAL_H

#include <iostream>  /* Print in cout */
#include <string>    /* string class */
#include <vector>    /* Vectorizing all operations */
#include <thread>    /* memory pools, multithread*/
#include <memory>    /* Smart Pointers*/
#include <complex>   /* Complex Numbers */
#include <math.h>       /* pow */
#include <fstream>      /* file management */
#include <assert.h>     /* assert */
#include <map>          /* map */

#include "Afhel.h"
#include "seal/dynarray.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"

using namespace std;
using namespace seal;


// Forward Declaration
class AfsealCtxt;
class AfsealPtxt;
class Afseal;
class AfsealPoly;


// Enum converters
static map<string, seal::compr_mode_type> compr_mode_map {
    {"none", compr_mode_type::none},
#ifdef SEAL_USE_ZLIB
    // Use ZLIB compression
    {"zlib", compr_mode_type::zlib},
#endif
#ifdef SEAL_USE_ZSTD
    // Use Zstandard compression
    {"zstd", compr_mode_type::zstd},
#endif
};
static map<seal::scheme_type, scheme_t> scheme_map_to_afhel {
   {seal::scheme_type::none, scheme_t::none},
   {seal::scheme_type::bfv,  scheme_t::bfv},
   {seal::scheme_type::ckks, scheme_t::ckks},
   {seal::scheme_type::bgv,  scheme_t::bgv},
};
static map<scheme_t, seal::scheme_type> scheme_map_to_seal {
   {scheme_t::none, seal::scheme_type::none},
   {scheme_t::bfv, seal::scheme_type::bfv},
   {scheme_t::ckks, seal::scheme_type::ckks},
   {scheme_t::bgv, seal::scheme_type::bgv},
};
static map<int, sec_level_type> sec_map{
    {0, seal::sec_level_type::none},
    {128, seal::sec_level_type::tc128},
    {192, seal::sec_level_type::tc192},
    {256, seal::sec_level_type::tc256},
};

// =============================================================================
// ======================= ABSTRACTION FOR PLAINTEXTS ==========================
// =============================================================================
class AfsealPtxt: public AfPtxt, public seal::Plaintext{
 public:
  using seal::Plaintext::Plaintext;
  virtual ~AfsealPtxt() = default;
  void set_scale(double new_scale){
    this->scale() = new_scale;
  };
};


// =============================================================================
// ====================== ABSTRACTION FOR CIPHERTEXTS ==========================
// =============================================================================
class AfsealCtxt: public AfCtxt, public seal::Ciphertext{
public:
  using seal::Ciphertext::Ciphertext;
  virtual ~AfsealCtxt() = default;
  void set_scale(double new_scale){
    this->scale() = new_scale;
  };

};


// =============================================================================
// ================================ AFSEALPOLY =================================
// =============================================================================
/// Wrapper for underlying polynomials that make up plaintexts and ciphertexts in SEAL
class AfsealPoly: public AfPoly {
 private:

  /// Parameter id associated with this AfsealPoly
  seal::parms_id_type parms_id;

  /// Pointer to the SEAL MemoryPool in which the polynomial is allocated
  seal::MemoryPoolHandle mempool;

  /// The last generated coeff_representation
  seal::DynArray<uint64_t> coeff_repr;

  /// The underlying ponomial
  seal::DynArray<uint64_t> eval_repr;

  /// True iff the last generated coeff_representaton is still valid
  /// (no operations were performed since the last generation)
  bool coeff_repr_valid = false;

  /// Degree of the polynomial / number of coefficients
  size_t coeff_count;

  /// Vector of the different RNS coefficient moduli
  vector<seal::Modulus> coeff_modulus;

  /// The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
  size_t coeff_modulus_count;

  /// Helper function to convert to coeff_repr
  void generate_coeff_repr(Afseal &afseal);

 public:
  // Note: All functions using an Afseal instance could also be defined as members of the Afseal class.

  /// Default Destructor
  virtual ~AfsealPoly();

  /// Copy constructor
  AfsealPoly(const AfsealPoly &other) = default;

  /// Copy operator
  AfsealPoly &operator=(const AfsealPoly &other) = default;

  /// Initializes a zero polynomial with sizes based on the parameters of Afseal
  /// Specifically, this uses "first_parms_id" / "first_parms_data" from SEALContext
  /// \param afseal Afseal object, used to access the context
  AfsealPoly(Afseal &afseal);

  /// Initializes a zero polynomial with sizes based on the parameters of the current ciphertext
  /// \param afseal Afseal object, used to access the context
  /// \param ref Ciphertext used as a reference to get get, e.g., coeff_modulus_count
  AfsealPoly(Afseal &afseal, const AfsealCtxt &ref);

  /// Creates a copy of the index-th polynomial comprising the Ciphertext
  /// \param afseal Afseal object, used to access the context
  /// \param ctxt  Ciphertext from which the polynomial should be copied
  /// \param index Index (starting at 0) of the polynomial to be copied
  AfsealPoly(Afseal &afseal, AfsealCtxt &ctxt, size_t index);

  /// Creates a copy of polynomial in the Plaintext
  /// \param afseal Afseal object, used to access the context
  /// \param ptxt  Plaintext from which the polynomial should be copied
  /// \param ref Ciphertext used as a reference to get get, e.g., coeff_modulus_count
  AfsealPoly(Afseal &afseal, AfsealPtxt &ptxt, const AfsealCtxt &ref) {
    // TODO: Remove this, as it makes no sense! Can just get all info from ptxt and afseal.context!
    throw runtime_error("FUNCTION REMOVED.");
  }

  /// Creates a copy of polynomial in the Plaintext
  /// \param afseal Afseal object, used to access the context
  /// \param ptxt  Plaintext from which the polynomial should be copied
  AfsealPoly(Afseal &afseal, AfsealPtxt &ptxt);

  //TODO: Constructor from a vector of complex values, defining the coefficients directly?

  /// Export polynomial to a vector of complex values
  /// \return vector of the (complex) coefficients of the polynomial
  vector<complex<double>> to_coeff_list(Afhel &afseal);

  /// get individual coefficient
  /// \param i index of the coefficient
  /// \return the i-th coefficient
  complex<double> get_coeff(Afhel &afseal, size_t i);

  /// set individual coefficient
  /// \param i index of the coefficient
  void set_coeff(Afhel &afseal, complex<double> &val, size_t i);

  // ----------- OPERATIONS -------------
  //inplace ops -> result in first operand
  void add_inplace(const AfPoly &other);
  void subtract_inplace(const AfPoly &other);
  void multiply_inplace(const AfPoly &other);

  bool invert_inplace();

   /// Degree of the polynomial / number of coefficients
  size_t get_coeff_count(){return this->coeff_count;}

  /// The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
  size_t get_coeff_modulus_count(){return this->coeff_modulus_count;}
};


// =============================================================================
// ================== ABSTRACTION FOR HOMOMORPHIC ENCR. LIBS ===================
// =============================================================================

// DYNAMIC CASTING
inline AfsealCtxt& _dyn_c(AfCtxt& c){return dynamic_cast<AfsealCtxt&>(c);};
inline AfsealPtxt& _dyn_p(AfPtxt& p){return dynamic_cast<AfsealPtxt&>(p);};

class Afseal: public Afhel {

 private:
  // --------------------------- ATTRIBUTES -----------------------------

  shared_ptr<seal::SEALContext> context = NULL;     /**< Context. Used for init*/
  shared_ptr<seal::BatchEncoder> bfvEncoder = NULL; /**< Rotation in Batching. */
  shared_ptr<seal::CKKSEncoder> ckksEncoder = NULL; /**< Rotation in Batching. */
  shared_ptr<seal::BatchEncoder> bgvEncoder = NULL;  
  
  shared_ptr<seal::KeyGenerator> keyGenObj = NULL;  /**< Key Generator Object.*/
  shared_ptr<seal::SecretKey> secretKey = NULL;     /**< Secret key.*/
  shared_ptr<seal::PublicKey> publicKey = NULL;     /**< Public key.*/
  shared_ptr<seal::RelinKeys> relinKeys = NULL;     /**< Relinearization object*/
  shared_ptr<seal::GaloisKeys> rotateKeys = NULL;   /**< Galois key for batching*/

  shared_ptr<seal::Encryptor> encryptor = NULL;     /**< Requires a Public Key.*/
  shared_ptr<seal::Evaluator> evaluator = NULL;     /**< Requires a context.*/
  shared_ptr<seal::Decryptor> decryptor = NULL;     /**< Requires a Secret Key.*/

  // ------------------ STREAM OPERATORS OVERLOAD -----------------------
  friend ostream &operator<<(ostream &outs, Afseal const &af);
  friend istream &operator>>(istream &ins, Afseal const &af);


 public:
  vector<uint64_t> qi;

  // ----------------------- CLASS MANAGEMENT ---------------------------
  Afseal();
  Afseal(const Afseal &otherAfseal);
  Afseal &operator=(const Afseal &assign) = default;
  Afseal(Afseal &&source) = default;
  virtual ~Afseal();

  // -------------------------- CRYPTOGRAPHY ---------------------------
  // CONTEXT GENERATION
  string ContextGen(
    scheme_t scheme, uint64_t poly_modulus_degree = 1024, 
    uint64_t plain_modulus_bit_size = 0, uint64_t plain_modulus = 0, 
    int sec = 128, vector<int> qi_sizes = {}, vector<uint64_t> qi_values = {});

  // KEY GENERATION
  void KeyGen();
  void relinKeyGen();
  void rotateKeyGen(vector<int> rot_steps = {});

  // ENCRYPTION
  void encrypt(AfPtxt &ptxt, AfCtxt &cipherOut);
  void encrypt_v(vector<shared_ptr<AfPtxt>> &ptxtV, vector<shared_ptr<AfCtxt>> &ctxtVOut);

  // DECRYPTION
  void decrypt(AfCtxt &ctxt, AfPtxt &plainOut);
  void decrypt_v(vector<shared_ptr<AfCtxt>> &ctxtV, vector<shared_ptr<AfPtxt>> &ptxtVOut);

  // NOISE MEASUREMENT
  int noise_level(AfCtxt &ctxt);

  // ------------------------------ CODEC -------------------------------
  // ENCODE
  // bfv
  void encode_i(vector<int64_t> &values, AfPtxt &plainOut);
  // ckks
  void encode_f(vector<double> &values, double scale, AfPtxt &ptxtVOut);
  void encode_c(vector<std::complex<double>> &values, double scale, AfPtxt &ptxtVOut);
  // bgv
  void encode_g(vector<int64_t> &values, AfPtxt &plainOut);

  // DECODE
  // bfv
  void decode_i(AfPtxt &ptxt, vector<int64_t> &valueVOut);
  // ckks
  void decode_f(AfPtxt &ptxt, vector<double> &valueVOut);
  void decode_c(AfPtxt &ptxt, vector<std::complex<double>> &valueVOut);
  // bgv
  void decode_g(AfPtxt &ptxt, vector<int64_t> &valueVOut);

  // AUXILIARY
  void data(AfPtxt &ptxt, uint64_t *dest);
  void allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest);
  
  // -------------------------- RELINEARIZATION -------------------------
  void relinearize(AfCtxt &ctxt);
  void relinearize_v(vector<shared_ptr<AfCtxt>> ctxtV);

  // ---------------------- HOMOMORPHIC OPERATIONS ----------------------
  // NEGATE
  void negate(AfCtxt &ctxt);
  void negate_v(vector<shared_ptr<AfCtxt>> &ctxtV);

  // SQUARE
  void square(AfCtxt &ctxt);
  void square_v(vector<shared_ptr<AfCtxt>> &ctxtV);

  // ADDITION
  void add(AfCtxt &ctxtInOut, AfCtxt &ctxt);
  void add_plain(AfCtxt &ctxtInOut, AfPtxt &ptxt);
  void add_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfCtxt>> &ctxtV2);
  void add_plain_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfPtxt>> &ptxtV2);

  // SUBTRACTION
  void sub(AfCtxt &ctxtInOut, AfCtxt &ctxt);
  void sub_plain(AfCtxt &ctxtInOut, AfPtxt &ptxt);
  void sub_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfCtxt>> &ctxtV2);
  void sub_plain_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfPtxt>> &ptxtV2);

  // MULTIPLICATION
  void multiply(AfCtxt &ctxtVInOut, AfCtxt &ctxt);
  void multiply_plain(AfCtxt &ctxtVInOut, AfPtxt &ptxt);
  void multiply_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfCtxt>> &ctxtV2);
  void multiply_plain_v(vector<shared_ptr<AfCtxt>> &ctxtVInOut, vector<shared_ptr<AfPtxt>> &ptxtV2);

  // ROTATE
  void rotate(AfCtxt &ctxt, int k);
  void rotate_v(vector<shared_ptr<AfCtxt>> &ctxtV, int k);
  void flip(AfCtxt &ctxt);
  void flip_v(vector<shared_ptr<AfCtxt>> &ctxtV);

  // POWER
  void exponentiate(AfCtxt &ctxt, uint64_t &expon);
  void exponentiate_v(vector<shared_ptr<AfCtxt>> &cipherV, uint64_t &expon);

  // CKKS -> Rescaling and mod switching
  void rescale_to_next(AfCtxt &ctxt);
  void rescale_to_next_v(vector<shared_ptr<AfCtxt>> &ctxtV);
  void mod_switch_to_next(AfCtxt &ctxt);
  void mod_switch_to_next_v(vector<shared_ptr<AfCtxt>> &ctxtV);
  void mod_switch_to_next_plain(AfPtxt &ptxt);
  void mod_switch_to_next_plain_v(vector<shared_ptr<AfPtxt>> &ptxtV);
  
  // --------------------------- VECTORIZATION --------------------------
  void vectorize(vector<shared_ptr<AfCtxt>> &ctxtVInOut,
                    function<void(AfCtxt)> f);
  void vectorize(vector<shared_ptr<AfPtxt>> &ptxtVInOut,
                    function<void(AfPtxt)> f);
  void vectorize(vector<shared_ptr<AfCtxt>> &ctxtVInOut,vector<shared_ptr<AfCtxt>> &ctxtV2,
                    function<void(AfCtxt, AfCtxt)> f);
  void vectorize(vector<shared_ptr<AfCtxt>> &ctxtVInOut,vector<shared_ptr<AfPtxt>> &ptxtV2,
                    function<void(AfCtxt, AfPtxt)> f);

  // -------------------------------- I/O -------------------------------
  // AUX
  seal::compr_mode_type get_compr_mode(string &mode);
  string get_compr_mode(seal::compr_mode_type &mode);

  // SAVE/LOAD CONTEXT
  size_t save_context(ostream &out_stream, string &compr_mode);
  size_t load_context(istream &in_stream, int sec=128);

  // SAVE/LOAD PUBLICKEY
  size_t save_public_key(ostream &out_stream, string &compr_mode);
  size_t load_public_key(istream &in_stream);

  // SAVE/LOAD SECRETKEY
  size_t save_secret_key(ostream &out_stream, string &compr_mode);
  size_t load_secret_key(istream &in_stream);

  // SAVE/LOAD RELINKEY
  size_t save_relin_keys(ostream &out_stream, string &compr_mode);
  size_t load_relin_keys(istream &in_stream);

  // SAVE/LOAD ROTKEYS
  size_t save_rotate_keys(ostream &out_stream, string &compr_mode);
  size_t load_rotate_keys(istream &in_stream);

  // SAVE/LOAD PLAINTEXT --> Could be achieved outside of Afseal
  size_t save_plaintext(ostream &out_stream, string &compr_mode, AfPtxt &pt);
  size_t load_plaintext(istream &in_stream, AfPtxt &pt);

  // SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afseal
  size_t save_ciphertext(ostream &out_stream, string &compr_mode, AfCtxt &ct);
  size_t load_ciphertext(istream &in_stream, AfCtxt &pt);

  // SIZES
  size_t sizeof_context(string &compr_mode);
  size_t sizeof_public_key(string &compr_mode);
  size_t sizeof_secret_key(string &compr_mode);
  size_t sizeof_relin_keys(string &compr_mode);
  size_t sizeof_rotate_keys(string &compr_mode);
  size_t sizeof_plaintext(string &compr_mode, AfPtxt &pt);
  size_t sizeof_ciphertext(string &compr_mode, AfCtxt &ct);

  // ----------------------------- AUXILIARY ----------------------------
  long maxBitCount(long poly_modulus_degree, int sec_level);

  // ckks
  double scale(AfCtxt &ctxt);
  void override_scale(AfCtxt &ctxt, double scale);

  // GETTERS
  bool batchEnabled();
  vector<uint64_t> get_qi();
  size_t get_nSlots();
  uint64_t get_plain_modulus();
  size_t get_poly_modulus_degree();
  scheme_t get_scheme();
  int get_sec();
  int total_coeff_modulus_bit_count();
  
  bool is_secretKey_empty() { return secretKey==NULL; }
  bool is_publicKey_empty() { return publicKey==NULL; }
  bool is_rotKey_empty() { return rotateKeys==NULL; }
  bool is_relinKeys_empty() { return relinKeys==NULL; }
  bool is_context_empty() { return context==NULL; }

  //KEY GETTERS/SETTERS
  inline shared_ptr<SEALContext>  get_context();
  inline shared_ptr<Evaluator>  get_evaluator();
  inline shared_ptr<Encryptor>  get_encryptor();
  inline shared_ptr<Decryptor>  get_decryptor();
  inline shared_ptr<BatchEncoder>  get_bfv_encoder();
  inline shared_ptr<CKKSEncoder>  get_ckks_encoder();
  inline shared_ptr<BatchEncoder>  get_bgv_encoder();
  inline shared_ptr<SecretKey>  get_secretKey();
  inline shared_ptr<PublicKey>  get_publicKey();
  inline shared_ptr<RelinKeys>  get_relinKeys();
  inline shared_ptr<GaloisKeys>  get_rotateKeys();
  void setpublicKey(seal::PublicKey &pubKey) { this->publicKey = make_shared<seal::PublicKey>(pubKey); }
  void setsecretKey(seal::SecretKey &secKey) { this->secretKey = make_shared<seal::SecretKey>(secKey); }
  void setrelinKeys(seal::RelinKeys &relKey) { this->relinKeys = make_shared<seal::RelinKeys>(relKey); }

  // ----------------------------- POLYNOMIALS ----------------------------
  friend class AfPoly;
  friend class AfsealPoly;

  // POLY OPS --> result in first operandshared_ptr
  void add_inplace(AfPoly &polyInOut, AfPoly &polyOther);
  void subtract_inplace(AfPoly &polyInOut, AfPoly &polyOther);
  void multiply_inplace(AfPoly &polyInOut, AfPoly &polyOther);
  void invert_inplace(AfPoly &polyInOut);

  // I/O
  void poly_to_ciphertext(AfPoly &p, AfCtxt &ctxt, size_t i);
  void poly_to_plaintext(AfPoly &p, AfPtxt &ptxt);
  AfsealPoly get_publicKey_poly(size_t index);
  AfsealPoly get_secretKey_poly();
  
  // Coefficient Access
  complex<double> get_coeff(AfPoly& poly, size_t i);
  void set_coeff(AfPoly& poly, complex<double> &val, size_t i);
  vector<complex<double>> to_coeff_list(AfPoly& poly);
};
#endif
