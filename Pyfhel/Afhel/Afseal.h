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

/*  License: GNU GPL v3
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

#include <iostream>    /* Print in std::cout */
#include <string>    /* std::string class */
#include <vector>    /* Vectorizing all operations */
#include <thread>    /* memory pools, multithread*/
#include <memory>    /* Smart Pointers*/
#include <complex>   /* Complex Numbers */

#include "seal/seal.h"

// Forward Declaration
class AfsealPoly;

/**
* @brief Abstraction For SEAL Homomorphic Encryption Library.
*
*  Afseal is a library that creates an abstraction over the basic
*  functionalities of SEAL as a Homomorphic Encryption library, such as
*  addition, multiplication, scalar product and others.
*
*/
class Afseal {

 private:
  // --------------------------- ATTRIBUTES -----------------------------

  std::shared_ptr<seal::SEALContext> context = NULL;           /**< Context. Used for init*/
  //TODO: Declare Encoder Ptr
  std::shared_ptr<seal::KeyGenerator> keyGenObj = NULL;        /**< Key Generator Object.*/
  std::shared_ptr<seal::SecretKey> secretKey = NULL;           /**< Secret key.*/
  std::shared_ptr<seal::PublicKey> publicKey = NULL;           /**< Public key.*/
  std::shared_ptr<seal::RelinKeys> relinKey = NULL;           /**< Relinearization object*/
  std::shared_ptr<seal::GaloisKeys> rotateKeys = NULL;         /**< Galois key for batching*/

  std::shared_ptr<seal::Encryptor> encryptor = NULL;           /**< Requires a Public Key.*/
  std::shared_ptr<seal::Evaluator> evaluator = NULL;           /**< Requires a context.*/
  std::shared_ptr<seal::Decryptor> decryptor = NULL;           /**< Requires a Secret Key.*/

  std::shared_ptr<seal::BatchEncoder> batchEncoder = NULL;     /**< Rotation in Batching. */


  long p;                          /**< All operations are modulo p^r */
  long m;                          /**< Cyclotomic index */

  long base;
  long sec;
  int intDigits;
  int fracDigits;

  bool flagBatch = false;         /**< Whether to use batching or not */



  // ------------------ STREAM OPERATORS OVERLOAD -----------------------
  /**
   * @brief An output stream operator, parsing the object into a std::string.
   * @param[out] outs output stream where to bulk the Afseal object
   * @param[in] af Afseal object to be exported
   * @see operator>>
   */
  friend std::ostream &operator<<(std::ostream &outs, Afseal const &af);

  /**
   * @brief An input stream operator, reading the parsed Afseal object
   *        from a std::string stream.
   * @param[in] ins input stream where to extract the Afseal object
   * @param[out] af Afseal object to contain the parsed one
   * @see operator<<
   */
  friend std::istream &operator>>(std::istream &ins, Afseal const &af);

 public:
  // ----------------------- CLASS MANAGEMENT ---------------------------
  /**
   * @brief Default constructor.
   */
  Afseal();

  /**
   * @brief Copy constructor.
   * @param[in] otherAfseal Afseal object to be copied
   */
  Afseal(const Afseal &otherAfseal);
  /**
   * @brief Overwrites current Afseal instance by a deep copy of a
   *          given instance.
   * @param[in] assign The Afseal instance to overwrite current instance
   */
  Afseal &operator=(const Afseal &assign) = default;
  /**
   * @brief Creates a new Afseal instance by moving a given instance.
   * @param[in] source The Afseal to move from
   */
  Afseal(Afseal &&source) = default;
  /**
  * @brief Default destructor.
  */
  virtual ~Afseal();


  // -------------------------- CRYPTOGRAPHY ---------------------------
  // CONTEXT GENERATION
  /**
   * @brief Performs generation of FHE context using SEAL functions.
   * @param[in] p ciphertext space base.
   * @param[in] r ciphertext space lifting .
   * @param[in] m m'th cyclotomic polynomial. Power of 2. Default 2048
   * @param[in]
   * @return Void.
   */
  void ContextGen(long p, long m = 2048, bool flagBatching = false,
                  long base = 2, long sec = 128, int intDigits = 64,
                  int fracDigits = 32);

  // KEY GENERATION
  /**
   * @brief Performs Key generation using SEAL functions vased on current context.
   *        As a result, a pair of Private/Public Keys are initialized and stored.
   * @return Void.
   */
  void KeyGen();

  // ENCRYPTION
  /**
   * @brief Enctypts a provided plaintext vector using pubKey as public key.
   *        The encryption is carried out with SEAL.
   * @param[in] plain1 plaintext vector to encrypt.
   * @return ciphertext the SEAL encrypted ciphertext.
   */
  seal::Ciphertext encrypt(seal::Plaintext &plain1);
  seal::Ciphertext encrypt(double &value1);
  seal::Ciphertext encrypt(int64_t &value1);
  seal::Ciphertext encrypt(std::vector<int64_t> &valueV);
  std::vector<seal::Ciphertext> encrypt(std::vector<int64_t> &valueV, bool &dummy_NoBatch);
  std::vector<seal::Ciphertext> encrypt(std::vector<double> &valueV);
  /**
   * @brief Enctypts a provided plaintext vector and stored in the
   *      provided ciphertext. The encryption is carried out with SEAL.
   * @param[in] plain1 plaintext vector to encrypt.
   * @param[in, out] cipher1 ciphertext to hold the result of encryption.
   * @return ciphertext the SEAL encrypted ciphertext.
   */
  void encrypt(seal::Plaintext &plain1, seal::Ciphertext &cipherOut);
  void encrypt(double &value1, seal::Ciphertext &cipherOut);
  void encrypt(int64_t &value1, seal::Ciphertext &cipherOut);
  void encrypt(std::vector<int64_t> &valueV, seal::Ciphertext &cipherOut);
  void encrypt(std::vector<int64_t> &valueV, std::vector<seal::Ciphertext> &cipherOut);
  void encrypt(std::vector<double> &valueV, std::vector<seal::Ciphertext> &cipherOut);

  // DECRYPTION
  /**
   * @brief Decrypts the ciphertext using secKey as secret key.
   * The decryption is carried out with SEAL.
   * @param[in] cipher1 a Ciphertext object from SEAL.
   * @return Plaintext the resulting of decrypting the ciphertext, a plaintext.
   */
  std::vector<int64_t> decrypt(seal::Ciphertext &cipher1);
  /**
   * @brief Decrypts the ciphertext using secKey as secret key and stores
   *         it in a provided Plaintext.
   * The decryption is carried out with SEAL.
   * @param[in] cipher1 a Ciphertext object from SEAL.
   * @param[in, out] plain1 a Plaintext object from SEAL.
   * @return Void.
   */
  void decrypt(seal::Ciphertext &cipher1, seal::Plaintext &plainOut);
  void decrypt(seal::Ciphertext &cipher1, int64_t &valueOut);
  void decrypt(seal::Ciphertext &cipher1, double &valueOut);
  void decrypt(seal::Ciphertext &cipher1, std::vector<int64_t> &valueVOut);
  void decrypt(std::vector<seal::Ciphertext> &cipherV, std::vector<int64_t> &valueVOut);
  void decrypt(std::vector<seal::Ciphertext> &cipherV, std::vector<double> &valueVOut);

  // NOISE MEASUREMENT
  int noiseLevel(seal::Ciphertext &cipher1);

  // ------------------------------ CODEC -------------------------------
  // ENCODE
  seal::Plaintext encode(int64_t &value1);
  seal::Plaintext encode(double &value1);
  seal::Plaintext encode(std::vector<int64_t> &values);
  std::vector<seal::Plaintext> encode(std::vector<int64_t> &values, bool dummy_NoBatch);
  std::vector<seal::Plaintext> encode(std::vector<double> &values);

  void encode(int64_t &value1, seal::Plaintext &plainOut);
  void encode(double &value1, seal::Plaintext &plainOut);
  void encode(std::vector<int64_t> &values, seal::Plaintext &plainOut);
  void encode(std::vector<int64_t> &values, std::vector<seal::Plaintext> &plainVOut);
  void encode(std::vector<double> &values, std::vector<seal::Plaintext> &plainVOut);

  // DECODE
  std::vector<int64_t> decode(seal::Plaintext &plain1);
  void decode(seal::Plaintext &plain1, int64_t &valOut);
  void decode(seal::Plaintext &plain1, double &valOut);
  void decode(seal::Plaintext &plain1, std::vector<int64_t> &valueVOut);
  void decode(std::vector<seal::Plaintext> &plain1, std::vector<int64_t> &valueVOut);
  void decode(std::vector<seal::Plaintext> &plain1, std::vector<double> &valueVOut);

  // -------------------------- RELINEARIZATION -------------------------
  void rotateKeyGen(int &bitCount);
  void relinKeyGen(int &bitCount, int &size);
  void relinearize(seal::Ciphertext &cipher1);


  // ---------------------- HOMOMORPHIC OPERATIONS ----------------------
  // SQUARE
  /**
   * @brief Square ciphertext values.
   * @param[in,out] cipher1 SEAL Ciphertext  whose values will get squared.
   * @return Void.
   */
  void square(seal::Ciphertext &cipher1);
  void square(std::vector<seal::Ciphertext> &cipherV);
  // NEGATE
  /**
  * @brief Negate values in a ciphertext
  * @param[in,out] c1  Ciphertext  whose values get negated.
  * @return Void.
  */
  void negate(seal::Ciphertext &cipher1);
  void negate(std::vector<seal::Ciphertext> &cipherV);


  // ADDITION
  /**
   * @brief Add second ciphertext to the first ciphertext.
   * @param[in,out] cipher1 First SEAL ciphertext.
   * @param[in] cipher2 Second SEAL ciphertext, to be added to the first.
   * @return Void.
   */
  void add(seal::Ciphertext &cipher1, seal::Ciphertext &cipher2);
  void add(seal::Ciphertext &cipher1, seal::Plaintext &plain2);
  void add(std::vector<seal::Ciphertext> &cipherV, seal::Ciphertext &cipherOut);
  void add(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Ciphertext> &cipherV2);
  void add(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Plaintext> &plainV2);

  // SUBSTRACTION
  /**
   * @brief Substract second ciphertext to the first ciphertext.
   * @param[in,out] cipher1 First SEAL ciphertext.
   * @param[in] cipher2 Second SEAL ciphertext, substracted to the first.
   * @return Void.
   */
  void sub(seal::Ciphertext &cipher1, seal::Ciphertext &cipher2);
  void sub(seal::Ciphertext &cipher1, seal::Plaintext &plain2);
  void sub(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Ciphertext> &cipherV2);
  void sub(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Plaintext> &plainV2);


  // MULTIPLICATION
  /**
   * @brief Multiply first ciphertext by the second ciphertext.
   * @param[in,out] cipher1 First SEAL Ciphertext.
   * @param[in] cipher2 Second SEAL Ciphertext , to be miltuplied to the first.
   * @return Void.
   */
  void multiply(seal::Ciphertext &cipher1, seal::Ciphertext &cipher2);
  void multiply(seal::Ciphertext &cipher1, seal::Plaintext &plain1);
  void multiply(std::vector<seal::Ciphertext> &cipherV1, seal::Ciphertext &cipherOut);
  void multiply(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Ciphertext> &cipherV2);
  void multiply(std::vector<seal::Ciphertext> &cipherVInOut, std::vector<seal::Plaintext> &plainV2);

  // ROTATE
  /**
   * @brief Rotate ciphertext by k spaces.
   * Overflowing values are added at the other side
   * @param[in,out] c1 SEAL Ciphertext  whose values get rotated.
   * @param[in] k number of spaces to rotate
   * @return Void.
   */
  void rotate(seal::Ciphertext &cipher1, int &k);
  void rotate(std::vector<seal::Ciphertext> &cipherV, int &k);


  // POLYNOMIALS
  /**
   * @brief Compute polynomial over a cyphertext
   * @param[in] coeffPoly Vector of long coefficients for the polynomial
   * @param[in,out] c1 SEAL Ciphertext  whose values get applied the polynomial.
   * @return void.
   */
  void exponentiate(seal::Ciphertext &cipher1, uint64_t &expon);
  void exponentiate(std::vector<seal::Ciphertext> &cipherV, uint64_t &expon);
  void polyEval(seal::Ciphertext &cipher1, std::vector<int64_t> &coeffPoly);
  void polyEval(seal::Ciphertext &cipher1, std::vector<double> &coeffPoly);

  // -------------------------------- I/O -------------------------------
  // SAVE ENVIRONMENT
  /**
   * @brief Saves the context and G polynomial in a .aenv file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool saveContext(std::string fileName);
  bool ssaveContext(std::ostream &contextFile);

  // RESTORE ENVIRONMENT
  /**
   * @brief Restores the context extracted form ea (containing m, p and r)
   *  and G polynomial from a .aenv file.
    * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool restoreContext(std::string fileName);
  bool srestoreContext(std::istream &contextFile);

  // PUBLIC KEY
  /**
   * @brief Saves the public key in a .apub file.
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool savepublicKey(std::string fileName);
  bool ssavepublicKey(std::ostream &keyFile);

  /**
   * @brief Restores the public key from a .apub file.
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool restorepublicKey(std::string fileName);
  bool srestorepublicKey(std::istream &keyFile);

  // SECRET KEY
  /**
   * @brief Saves the secretKey in a .apub file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool savesecretKey(std::string fileName);
  bool ssavesecretKey(std::ostream &keyFile);

  /**
   * @brief Restores the secretKey from a .apub file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool restoresecretKey(std::string fileName);
  bool srestoresecretKey(std::istream &keyFile);

  // PLAINTEXTS
  /**
   * @brief Saves the plaintext in a file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool savePlaintext(std::string fileName, seal::Plaintext &plain);
  bool ssavePlaintext(std::ostream &plaintextFile, seal::Plaintext &plain);

  /**
   * @brief Restores the plaintext from a file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool restorePlaintext(std::string fileName, seal::Plaintext &plain);
  bool srestorePlaintext(std::istream &plaintextFile, seal::Plaintext &plain);


  // CIPHERTEXTS
  /**
   * @brief Saves the ciphertext in a file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool saveCiphertext(std::string fileName, seal::Ciphertext &ctxt);
  bool ssaveCiphertext(std::ostream &ctxtFile, seal::Ciphertext &ctxt);

  /**
   * @brief Restores the ciphertext from a file
   * @param[in] fileName name of the file without the extention
   * @return BOOL 1 if all ok, 0 otherwise
   */
  bool restoreCiphertext(std::string fileName, seal::Ciphertext &ctxt);
  bool srestoreCiphertext(std::istream &ctxtFile, seal::Ciphertext &ctxt);

  bool saverelinKey(std::string fileName);
  bool ssaverelinKey(std::ostream &keyFile);
  bool restorerelinKey(std::string fileName);
  bool srestorerelinKey(std::istream &keyFile);

  bool saverotateKey(std::string fileName);
  bool ssaverotateKey(std::ostream &keyFile);
  bool restorerotateKey(std::string fileName);
  bool srestorerotateKey(std::istream &keyFile);

  // ----------------------------- AUXILIARY ----------------------------
  bool batchEnabled();
  long relinBitCount();
  // GETTERS
  seal::SecretKey getsecretKey();
  seal::PublicKey getpublicKey();
  seal::RelinKeys getrelinKey();
  seal::GaloisKeys getrotateKeys();
  int getnSlots();
  int getp();
  int getm();
  int getbase();
  int getsec();
  int getintDigits();
  int getfracDigits();
  bool getflagBatch();

  bool is_secretKey_empty() { return secretKey==NULL; }
  bool is_publicKey_empty() { return publicKey==NULL; }
  bool is_rotKey_empty() { return rotateKeys==NULL; }
  bool is_relinKey_empty() { return relinKey==NULL; }
  bool is_context_empty() { return context==NULL; }

  //SETTERS
  void setpublicKey(seal::PublicKey &pubKey) { this->publicKey = std::make_shared<seal::PublicKey>(pubKey); }
  void setsecretKey(seal::SecretKey &secKey) { this->secretKey = std::make_shared<seal::SecretKey>(secKey); }
  void setrelinKey(seal::RelinKeys &relKey) { this->relinKey = std::make_shared<seal::RelinKeys>(relKey); }

  friend class AfsealPoly;

  // POLY CONSTRUCTION -->
  AfsealPoly empty_poly(const seal::Ciphertext &ref);
  AfsealPoly poly_from_ciphertext(seal::Ciphertext &ctxt, int64_t pos);
  AfsealPoly poly_from_plaintext(seal::Plaintext &ptxt, const seal::Ciphertext &ref);
  //AfsealPoly poly_from_coeff_vector(std::vector<std::complex<double>> &coeff_vector);
  std::vector<AfsealPoly> poly_from_ciphertext(seal::Ciphertext &ctxt);

  // POLY OPS --> implement checks for compatibility.
  AfsealPoly add(AfsealPoly &p1, AfsealPoly &p2);
  AfsealPoly subtract(AfsealPoly &p1, AfsealPoly &p2);
  AfsealPoly multiply(AfsealPoly &p1, AfsealPoly &p2);
  AfsealPoly invert(AfsealPoly &p);

  //inplace ops -> result in first operand
  void add_inplace(AfsealPoly &p1, AfsealPoly &p2);
  void subtract_inplace(AfsealPoly &p1, AfsealPoly &p2);
  void multiply_inplace(AfsealPoly &p1, AfsealPoly &p2);
  void invert_inplace(AfsealPoly &p);

  // I/O
  void poly_to_ciphertext(AfsealPoly &p, seal::Ciphertext &ctxt, int64_t pos);
  void poly_to_plaintext(AfsealPoly &p, seal::Plaintext &ptxt);

  // Coefficient Access
  std::complex<double> get_coeff(AfsealPoly& poly, size_t i);
  void set_coeff(AfsealPoly& poly, std::complex<double> &val, size_t i);
  std::vector<std::complex<double>> to_coeff_list(AfsealPoly& poly);
};

/// Wrapper for the underlying polynomials that make up plaintexts and ciphertexts in SEAL
class AfsealPoly {
 private:

  /// Parameter id associated with this AfsealPoly
  seal::parms_id_type parms_id;

  /// Pointer to the SEAL MemoryPool in which the polynomial is allocated
  seal::MemoryPoolHandle mempool;

  /// Pointer to the last generated coeff_representation
  seal::util::CoeffIter coeff_repr_coeff_iter;

  /// Pointer to the underlying ponomial
  seal::util::CoeffIter eval_repr_coeff_iter;

  /// True iff the last generated coeff_representaton is still valid
  /// (no operations were performed since the last generation)
  bool coeff_repr_valid = false;

  /// Degree of the polynomial / number of coefficients
  size_t coeff_count;

  std::vector<seal::Modulus> coeff_modulus;

  /// The number of coefficient moduli q_i (i.e., coeff_modulus.size() )
  size_t coeff_modulus_count;

  /// Helper function to convert to coeff_repr
  void generate_coeff_repr(Afseal &afseal);

 public:
  // Note: All functions using an Afseal instance could also be defined as members of the Afseal class.

  /// Default Destructor
  ~AfsealPoly() = default;

  /// Copy constructor
  AfsealPoly(AfsealPoly &other);

  /// Copy operator
  AfsealPoly &operator=(AfsealPoly &other);

  /// Initializes a zero polynomial with sizes based on the parameters of the current ciphertext
  /// \param afseal Afseal object, used to access the context
  /// \param ref Ciphertext used as a reference to get get, e.g., coeff_modulus_count
  AfsealPoly(Afseal &afseal, const seal::Ciphertext &ref);

  /// Creates a copy of the index-th polynomial comprising the Ciphertext
  /// \param afseal Afseal object, used to access the context
  /// \param ctxt  Ciphertext from which the polynomial should be copied
  /// \param index Index (starting at 0) of the polynomial to be copied
  AfsealPoly(Afseal &afseal, seal::Ciphertext &ctxt, size_t index);

  /// Creates a copy of polynomial in the Plaintext
  /// \param afseal Afseal object, used to access the context
  /// \param ptxt  Plaintext from which the polynomial should be copied
  /// \param ref Ciphertext used as a reference to get get, e.g., coeff_modulus_count
  AfsealPoly(Afseal &afseal, seal::Plaintext &ptxt, const seal::Ciphertext &ref);

  //TODO: Constructor from a vector of complex values, defining the coefficients directly?

  /// Export polynomial to a vector of complex values
  /// \return vector of the (complex) coefficients of the polynomial
  std::vector<std::complex<double>> to_coeff_list(Afseal &afseal);

  /// get individual coefficient
  /// \param i index of the coefficient
  /// \return the i-th coefficient
  std::complex<double> get_coeff(Afseal &afseal, size_t i);

  /// set individual coefficient
  /// \param i index of the coefficient
  void set_coeff(Afseal &afseal, std::complex<double> &val, size_t i);

  // ----------- OPERATIONS -------------
  //inplace ops -> result in first operand
  void add_inplace(const AfsealPoly &other);

  void subtract_inplace(const AfsealPoly &other);

  void multiply_inplace(const AfsealPoly &other);

  bool invert_inplace();

};
#endif
