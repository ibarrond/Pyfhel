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
 
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <random>
#include <limits>

#include "../SEAL/SEAL/seal.h"

using namespace std;
using namespace seal;

/**
* @brief Abstraction For SEAL Homomorphic Encryption Library.
*
*  Afseal is a library that creates an abstraction over the basic
*  functionalities of SEAL as a Homomorphic Encryption library, such as
*  addition, multiplication, scalar product and others.
*
*/
class Afseal{ 

    private: 
        // -------------------------- ATTRIBUTES ----------------------------
        /** @defgroup ATTRIBUTES Afseal member objects;
         *  @{
         */
        SEALContext* context;             /**< Context object. Used for init*/
  
        IntegerEncoder* intEncoder;       /**< Integer Encoding.*/
        FractionalEncoder* fracEncoder;   /**< Fractional Encoding.*/

        KeyGenerator* keyGenObj;          /**< Key Generator Object.*/
        SecretKey* secretKey;             /**< Secret key.*/
        PublicKey* publicKey;             /**< Public key.*/
        EvaluationKeys* relinKey;         /**< Relinearization object*/
        GaloisKeys* galKeys;              /**< Galois key for batching*/

        Encryptor* encryptor;             /**< Requires a Public Key.*/
        Evaluator* evaluator;             /**< Requires a context.*/
        Decryptor* decryptor;             /**< Requires a Secret Key.*/

        PolyCRTBuilder* crtBuilder;       /**< used for Batching. */

        int32_t p;                        /**< All operations are modulo p^r */
        int32_t m;                        /**< Cyclotomic index */

        /** @} ATTRIBUTES*/


        // ------------------ STREAM OPERATORS OVERLOAD ----------------------
        /** @defgroup STREAM_OPERATORS_OVERLOAD
         * import/export to string streams
         *  @{
         */
        /**
         * @brief An output stream operator, parsing the object into a string.
         * @param[out] outs output stream where to bulk the Afseal object
         * @param[in] af Afseal object to be exported
         * @see operator>>
         */
        friend std::ostream& operator<< (std::ostream& outs, Afseal const& af);

        /**
         * @brief An input stream operator, reading the parsed Afseal object from
         *        a string stream.
         * @param[in] ins input stream where to extract the Afseal object
         * @param[out] af Afseal object to contain the parsed one
         * @see operator<<
         */
        friend std::istream& operator>> (std::istream& ins, Afseal const& af);
        /** @} STREAM_OPERATORS_OVERLOAD*/



    public:
        // ----------------------- CLASS MANAGEMENT --------------------------
        /** @defgroup CLASS_MANAGEMENT Constructor, Copy and Destructor.
         *  @{
         */
        /**
         * @brief Default constructor.
         */
        Afseal();

        /**
         * @brief Copy constructor.
         * @param[in] otherAfseal Afseal object to be copied
         */
        Afseal(Afseal &otherAfseal);

        /**
        * @brief Default destructor.
        */
        virtual ~Afseal();
        /** @} CLASS_MANAGEMENT*/



        // -------------------------- CRYPTOGRAPHY ---------------------------
        /** @defgroup CRYPTOGRAPHY ContextGen, KeyGen, Encrypt and Decrypt
         *  @{
         */
        // CONTEXT GENERATION
        /**
         * @brief Performs generation of FHE context using SEAL functions.
         *          As a result, context, ea and nSlots are initialized.
         * @param[in] p ciphertext space base.
         * @param[in] r ciphertext space lifting .
         * @param[in] m m'th cyclotomic polynomial. Power of 2. Default 2048
         * @param[in] 
         * @return Void.
         */
        void ContextGen(long p, long m = 2048, long sec=128,
                                bool flagBatching=false);

        // KEY GENERATION
        /**
         * @brief Performs Key generation using SEAL functions vased on current context.
         *          As a result, a pair of Private/Public Keys are initialized and stored.
         * @return Void.
         */
        void KeyGen();

        // ENCRYPTION
        /** @defgroup ENCRYPTION
         *  @{
         */
        /**
         * @brief Enctypts a provided plaintext vector using pubKey as public key.
         *      The encryption is carried out with SEAL.
         * @param[in] plain1 plaintext vector to encrypt.
         * @return ciphertext the SEAL encrypted ciphertext.
         */
        Ciphertext encrypt(Plaintext& plain1);
        /**
         * \overload Ciphertext encrypt(Plaintext plain1)
         */
        Ciphertext encrypt(double& value1);
        /**
         * \overload Ciphertext encrypt(Plaintext plain1)
         */
        Ciphertext encrypt(int64_t& value1);
        /**
         * @brief Enctypts a provided plaintext vector and stored in the
         *      provided ciphertext. The encryption is carried out with SEAL. 
         * @param[in] plain1 plaintext vector to encrypt.
         * @param[in, out] cipher1 ciphertext to hold the result of encryption.
         * @return ciphertext the SEAL encrypted ciphertext.
         */
        void encrypt(Plaintext& plain1, Ciphertext& cipherOut);
        /**
         * \overload void encrypt(Plaintext& plain1, Ciphertext& cipher1)
         */
        void encrypt(double& value1, Ciphertext& cipherOut);
        /**
         * \overload void encrypt(Plaintext& plain1, Ciphertext& cipher1)
         */
        void encrypt(int64_t& value1, Ciphertext& cipherOut);
        /** @} ENCRYPTION*/


        // DECRYPTION
        /** @defgroup DECRYPTION
         *  @{
         */
        /**
         * @brief Decrypts the ciphertext using secKey as secret key.
         * The decryption is carried out with SEAL.
         * @param[in] cipher1 a Ciphertext object from SEAL.
         * @return Plaintext the resulting of decrypting the ciphertext, a plaintext.
         */
        Plaintext decrypt(Ciphertext& cipher1);
        /**
         * @brief Decrypts the ciphertext using secKey as secret key and stores
         *         it in a provided Plaintext.
         * The decryption is carried out with SEAL.
         * @param[in] cipher1 a Ciphertext object from SEAL.
         * @param[in, out] plain1 a Plaintext object from SEAL.
         * @return Void.
         */
        void decrypt(Ciphertext& cipher1, Plaintext& plainOut);
        /**
         * \overload void Afseal::decrypt(Ciphertext& cipher1, Plaintext& plain1)
         */
        void decrypt(Ciphertext& cipher1, int64_t& valueOut); 
        /**
         * \overload void Afseal::decrypt(Ciphertext& cipher1, Plaintext& plain1)
         */
        void decrypt(Ciphertext& cipher1, double& valueOut);
        /** @} DECRYPTION*/
        /** @} CRYPTOGRAPHY*/


        int noiseLevel(Ciphertext& cipher1);

        // ----------------------------- ENCODING -----------------------------
        Plaintext encode(int64_t& value1);
        Plaintext encode(double& value1);
        Plaintext encode(std::vector<std::int64_t> &values);
        void encode(int64_t& value1, Plaintext& plainOut);
        void encode(double& value1, Plaintext& plainOut);
        void encode(std::vector<std::int64_t> &values, Plaintext& plainOut);

        void decode(Plaintext& plain1, int64_t& valOut);
        void decode(Plaintext& plain1, double& valOut);
        
        void relinKeyGen(int& bitCount);
        void relinearize(Ciphertext& cipher1);
        void galoisKeyGen(int& bitCount);
        // ---------------------- HOMOMORPHIC OPERATIONS ----------------------
        /** @defgroup HOMOMORPHIC_OPERATIONS
         *  @{
         */
        // ADDITION
        /**
         * @brief Add second ciphertext to the first ciphertext.
         * @param[in,out] cipher1 First SEAL ciphertext.
         * @param[in] cipher2 Second SEAL ciphertext, to be added to the first.
         * @return Void.
         */
        void add(Ciphertext& cipher1, Ciphertext& cipher2);
        void add(Ciphertext& cipher1, Plaintext& plain2);
        void add(std::vector<Ciphertext>& cipherV1, Ciphertext& cipherOut);

        // MULTIPLICATION
        /**
         * @brief Multiply first ciphertext by the second ciphertext.
         * @param[in,out] cipher1 First SEAL Ciphertext.
         * @param[in] cipher2 Second SEAL Ciphertext , to be miltuplied to the first.
         * @return Void.
         */
        void multiply(Ciphertext& cipher1, Ciphertext& cipher2);
        void multiply(Ciphertext& cipher1, Plaintext& plain1);
        void multiply(std::vector<Ciphertext>& cipherV1, Ciphertext& cipherOut);

        // SQUARE
        /**
         * @brief Square ciphertext values.
         * @param[in,out] cipher1 SEAL Ciphertext  whose values will get squared.
         * @return Void.
         */
        void square(Ciphertext& cipher1);

        // NEGATE
        /**
        * @brief Negate values in a ciphertext
        * @param[in,out] c1  Ciphertext  whose values get negated.
        * @return Void.
        */
        void negate(Ciphertext& cipher1);

        // COMPARE EQUALS
        /**
         * @brief Compare ciphertext c1 and ciphertext c2.
         * @param[in] c1 SEAL Ciphertext.
         * @param[in] c2 SEAL Ciphertext.
         * @param[in] comparePkeys if true then keys will be compared.
         * @return BOOL with the comparison c1 == c2
         */
        bool equalsTo(Ciphertext c1, Ciphertext c2, bool comparePkeys=true);

        // ROTATE
        /**
         * @brief Rotate ciphertext by c spaces.
         * Overflowing values are added at the other side
         * @param[in,out] c1 SEAL Ciphertext  whose values get rotated.
         * @param[in] c number of spaces to rotate
         * @return Void.
         */
        void rotate(Ciphertext c1, long c);

        // SHIFT
        /**
         * @brief Rotate ciphertext by c spaces.
         * Overflowing values are added at the other side
         * @param[in,out] c1 SEAL Ciphertext  whose values get rotated.
         * @param[in] c number of spaces to rotate
         * @return Void.
         */
        void shift(Ciphertext c1, long c);

        /**
         * @brief Compute polynomial over a cyphertext
         * @param[in] coeffPoly Vector of long coefficients for the polynomial
         * @param[in,out] c1 SEAL Ciphertext  whose values get applied the polynomial.
         * @return void.
         */
        void polyEval(Ciphertext c1, vector<long> const& coeffPoly);


        // -------------------------------- I/O -------------------------------
        // SAVE ENVIRONMENT
        /**
         * @brief Saves the context and G polynomial in a .aenv file
         * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool saveContext(string fileName);

        // RESTORE ENVIRONMENT
        /**
         * @brief Restores the context extracted form ea (containing m, p and r)
         *  and G polynomial from a .aenv file.
          * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool restoreContext(string fileName);

        // PUBLIC KEY
        /**
         * @brief Saves the public key in a .apub file.
         * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool savepublicKey(string fileName);

        /**
         * @brief Restores the public key from a .apub file.
         * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool restorepublicKey(string fileName);

        // SECRET KEY
        /**
         * @brief Saves the secretKey in a .apub file
         * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool savesecretKey(string fileName);

        /**
         * @brief Restores the secretKey from a .apub file
         * @param[in] fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool restoresecretKey(string fileName);

        /**
         * @brief Fills a vector with random values up to nSlots
         * @param[in] array vector to be filled with random values.
         * @return Void.
         */
        void random(vector<long>& array) const;


        // ----------------------------- AUXILIARY ----------------------------
        bool batchEnabled();
        long relinBitCount();
        // GETTERS
        /**
         * @brief Getter for secretKey, the key used to decrypt vectors.
         * @return secKey the secret key of the key pair.
         */
        SecretKey getsecretKey();

        /**
         * @brief Getter for for publicKey, the key used to encrypt vectors.
         * @return pubKey the public key of the key pair.
         */
        PublicKey getpublicKey();

        /**
         * @brief Getter for for evaluationKeys, the key used to perform operations.
         * @return relinKey the evaluation key.
         */
        EvaluationKeys getrelinKey(); 

        /**
         * @brief Getter for # of slots in ctxt vectors.
         * @return number of plaintext slots.
         */
        long getnSlots();

        /**
         * @brief Getter for p, cyphertext space modulus.
         * @return p cyphertext space modulus.
         */
        long getp();

        /**
         * @brief Getter for c, cyphertext space exponent.
         * @return r cyphertext space exponent.
         */
        long getr();

        /**
         * @brief Getter for m, cyclotomical polynomial exponent.
         * @return m cyclotomical polynomial exponent.
         */
        long getm();

        /**
         * @brief Getter for nSlots, number of plaintext slots in batching.
         * @return nSlots number of plaintext slots in batching.
         */
        long getnSlots();

        //SETTERS
        /**
         * @brief Setter for publicKey, the key used to encrypt vectors.
         * @param[in] pubKey public key of the key pair.
         * @return Void.
         */
        void setpublicKey(PublicKey& pubKey);

        /**
         * @brief Setter for secretKey, the key used to decrypt vectors.
         * @param[in] secKey secret key of the key pair.
         * @return Void.
         */
        void setsecretKey(SecretKey& secKey);

        /**
         * @brief Setter for relinKey, the key used to decrypt vectors.
         * @param[in] secKey secret key of the key pair.
         * @return Void.
         */
        void setrelinKey(EvaluationKeys& relKey);

};
#endif