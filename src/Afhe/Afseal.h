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
        // --------------------------- ATTRIBUTES -----------------------------
        /** @defgroup ATTRIBUTES Afseal member objects;
         *  @{
         */
        SEALContext* context;           /**< Context object. Used for init*/
  
        IntegerEncoder* intEncoder;     /**< Integer Encoding.*/
        FractionalEncoder* fracEncoder; /**< Fractional Encoding.*/

        KeyGenerator* keyGenObj;        /**< Key Generator Object.*/
        SecretKey* secretKey;           /**< Secret key.*/
        PublicKey* publicKey;           /**< Public key.*/
        EvaluationKeys* relinKey;       /**< Relinearization object*/
        GaloisKeys* galKeys;            /**< Galois key for batching*/

        Encryptor* encryptor;           /**< Requires a Public Key.*/
        Evaluator* evaluator;           /**< Requires a context.*/
        Decryptor* decryptor;           /**< Requires a Secret Key.*/

        PolyCRTBuilder* crtBuilder;     /**< used for Batching. */

        int p;                          /**< All operations are modulo p^r */
        int m;                          /**< Cyclotomic index */

        bool flagBatching = false;      /**< Whether to use batching or not */

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
        friend ostream& operator<< (ostream& outs, Afseal const& af);

        /**
         * @brief An input stream operator, reading the parsed Afseal object from
         *        a string stream.
         * @param[in] ins input stream where to extract the Afseal object
         * @param[out] af Afseal object to contain the parsed one
         * @see operator<<
         */
        friend istream& operator>> (istream& ins, Afseal const& af);
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
        void ContextGen(long p, long m = 2048, long base = 2, long sec=128,
                        int intDigits = 64, int fracDigits = 32,
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
        Ciphertext encrypt(double& value1);
        Ciphertext encrypt(int64_t& value1);
        Ciphertext encrypt(vector<int64_t>& valueV);
        vector<Ciphertext> encrypt(vector<int64_t>& valueV, bool& dummy_NoBatch);
        vector<Ciphertext> encrypt(vector<double>& valueV);
        /**
         * @brief Enctypts a provided plaintext vector and stored in the
         *      provided ciphertext. The encryption is carried out with SEAL. 
         * @param[in] plain1 plaintext vector to encrypt.
         * @param[in, out] cipher1 ciphertext to hold the result of encryption.
         * @return ciphertext the SEAL encrypted ciphertext.
         */
        void encrypt(Plaintext& plain1, Ciphertext& cipherOut);
        void encrypt(double& value1, Ciphertext& cipherOut);
        void encrypt(int64_t& value1, Ciphertext& cipherOut);
        void encrypt(vector<int64_t>& valueV, Ciphertext& cipherOut);
        void encrypt(vector<int64_t>& valueV, vector<Ciphertext>& cipherOut);
        void encrypt(vector<double>& valueV, vector<Ciphertext>& cipherOut);

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
        void decrypt(Ciphertext& cipher1, int64_t& valueOut); 
        void decrypt(Ciphertext& cipher1, double& valueOut);
        void decrypt(Ciphertext& cipher1, vector<int64_t>& valueVOut); 
        void decrypt(vector<Ciphertext>& cipherV, vector<int64_t>& valueVOut);
        void decrypt(vector<Ciphertext>& cipherV, vector<double>& valueVOut);


        // NOISE MEASUREMENT
        int noiseLevel(Ciphertext& cipher1);

        // ------------------------------ CODEC -------------------------------
        // ENCODE 
        Plaintext encode(int64_t& value1);
        Plaintext encode(double& value1);
        Plaintext encode(vector<int64_t> &values);
        vector<Plaintext> encode(vector<int64_t> &values, bool dummy_NoBatch);
        vector<Plaintext> encode(vector<double> &values);

        void encode(int64_t& value1, Plaintext& plainOut);
        void encode(double& value1, Plaintext& plainOut);
        void encode(vector<int64_t> &values, Plaintext& plainOut);
        void encode(vector<int64_t> &values, vector<Plaintext>& plainVOut);
        void encode(vector<double> &values, vector<Plaintext>& plainVOut);

        // DECODE 
        void decode(Plaintext& plain1, int64_t& valOut);
        void decode(Plaintext& plain1, double& valOut);
        void decode(Plaintext& plain1, vector<int64_t> &valueVOut);
        void decode(vector<Plaintext>& plain1, vector<int64_t> &valueVOut);
        void decode(vector<Plaintext>& plain1, vector<double> &valueVOut);


        // -------------------------- RELINEARIZATION -------------------------
        void galoisKeyGen(int& bitCount);
        void relinKeyGen(int& bitCount);
        void relinearize(Ciphertext& cipher1);


        // ---------------------- HOMOMORPHIC OPERATIONS ----------------------
        // SQUARE
        /**
         * @brief Square ciphertext values.
         * @param[in,out] cipher1 SEAL Ciphertext  whose values will get squared.
         * @return Void.
         */
        void square(Ciphertext& cipher1);
        void square(vector<Ciphertext>& cipherV);
        // NEGATE
        /**
        * @brief Negate values in a ciphertext
        * @param[in,out] c1  Ciphertext  whose values get negated.
        * @return Void.
        */
        void negate(Ciphertext& cipher1);
        void negate(vector<Ciphertext>& cipherV);

        
        // ADDITION
        /**
         * @brief Add second ciphertext to the first ciphertext.
         * @param[in,out] cipher1 First SEAL ciphertext.
         * @param[in] cipher2 Second SEAL ciphertext, to be added to the first.
         * @return Void.
         */
        void add(Ciphertext& cipher1, Ciphertext& cipher2);
        void add(Ciphertext& cipher1, Plaintext& plain2);
        void add(vector<Ciphertext>& cipherV, Ciphertext& cipherOut);
        void add(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2);
        void add(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2);

        // SUBSTRACTION
        /**
         * @brief Substract second ciphertext to the first ciphertext.
         * @param[in,out] cipher1 First SEAL ciphertext.
         * @param[in] cipher2 Second SEAL ciphertext, substracted to the first.
         * @return Void.
         */
        void sub(Ciphertext& cipher1, Ciphertext& cipher2);
        void sub(Ciphertext& cipher1, Plaintext& plain2);
        void sub(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2);
        void sub(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2);
        

        // MULTIPLICATION
        /**
         * @brief Multiply first ciphertext by the second ciphertext.
         * @param[in,out] cipher1 First SEAL Ciphertext.
         * @param[in] cipher2 Second SEAL Ciphertext , to be miltuplied to the first.
         * @return Void.
         */
        void multiply(Ciphertext& cipher1, Ciphertext& cipher2);
        void multiply(Ciphertext& cipher1, Plaintext& plain1);
        void multiply(vector<Ciphertext>& cipherV1, Ciphertext& cipherOut);
        void multiply(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2);
        void multiply(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2);

        // ROTATE
        /**
         * @brief Rotate ciphertext by k spaces.
         * Overflowing values are added at the other side
         * @param[in,out] c1 SEAL Ciphertext  whose values get rotated.
         * @param[in] k number of spaces to rotate
         * @return Void.
         */
        void rotate(Ciphertext& cipher1, int& k);
        void rotate(vector<Ciphertext>& cipherV, int& k);


        // POLYNOMIALS
        /**
         * @brief Compute polynomial over a cyphertext
         * @param[in] coeffPoly Vector of long coefficients for the polynomial
         * @param[in,out] c1 SEAL Ciphertext  whose values get applied the polynomial.
         * @return void.
         */
        void exponentiate(Ciphertext cipher1, uint64_t& exponent);
        void exponentiate(vector<Ciphertext>& cipherV, uint64_t& expon);
        void polyEval(Ciphertext cipher1, vector<int64_t>& coeffPoly);


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
        SecretKey getsecretKey();
        PublicKey getpublicKey();
        EvaluationKeys getrelinKey(); 
        int getnSlots();
        int getp();
        int getm();
        bool getflagBatching();

        //SETTERS
        void setpublicKey(PublicKey& pubKey);
        void setsecretKey(SecretKey& secKey);
        void setrelinKey(EvaluationKeys& relKey);
        void setflagBatching(bool f_batch);

};
#endif