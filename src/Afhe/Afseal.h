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

        SEALContext *context;             /**< Context object. Used for init*/
  
        IntegerEncoder *intEncoder;       /**< Integer Encoding.*/
        FractionalEncoder *fracEncoder;   /**< Fractional Encoding.*/

        SecretKey *secretKey;             /**< Secret key.*/
        PublicKey *publicKey;             /**< Public key.*/

        Encryptor *encryptor;
        Evaluator *evaluator;
        Decryptor *decryptor;

        long p, r;                        /**< All operations are modulo p^r */
        long m;                           /**< Cyclotomic index */
        bool flagVerbose = false;         /**< Print messages on console */
        bool flagTime = false;            /**< Print timings on console */


        EvaluationKeys evRel;            /**< Evaluation auxiliars for relin.*/

        // ------------------ STREAM OPERATORS OVERLOAD ----------------------
        /**
         * @brief An output stream operator, parsing the object into a string.
         * @param[out] outs output stream where to bulk the Afseal object
         * @param[in] af Afseal object to be exported
         * @see operator>>
         */
        friend std::ostream& operator<< (std::ostream& outs, Afseal const& af);

        /**
         * @brief An input stream operator, reading the parsed Afseal object from a string.
         * @param[in] ins input stream where to extract the Afseal object
         * @param[out] af Afseal object to contain the parsed one
         * @see operator<<
         */
        friend std::istream& operator>> (std::istream& ins, Afseal const& af);



    public:
        // ----------------------- CLASS MANAGEMENT --------------------------
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


        // -------------------------- CRYPTOGRAPHY ---------------------------
        // CONTEXT GENERATION
        /**
         * @brief Performs generation of FHE context using SEAL functions.
         *          As a result, context, ea and nSlots are initialized.
         * @param[in] p ciphertext space base.
         * @param[in] r ciphertext space lifting .
         * @param[in] m (optional) use m'th cyclotomic polynomial. Default set by heuristics (-1)
         * @param[in] 
         * @return Void.
         */
        void ContextGen(long p, long r, long m = 2048);

        // KEY GENERATION
        /**
         * @brief Performs Key generation using SEAL functions vased on current context.
         *          As a result, a pair of Private/Public Keys are initialized and stored.
         * @return Void.
         */
        void KeyGen();

        // ENCRYPTION
        /**
         * @brief Enctypts a provided plaintext vector using pubKey as public key.
         *      The encryption is carried out with SEAL.
         * @param[in] plain1 plaintext vector to encrypt.
         * @return ciphertext the SEAL encrypted ciphertext.
         */
        Ciphertext encrypt(Plaintext plain1);

        // DECRYPTION
        /**
         * @brief Decrypts the ciphertext using secKey as secret key.
         * The decryption is carried out with SEAL.
         * @param[in] cipher1 a Ciphertext object from SEAL.
         * @return vector<long> the resulting of decrypting the ciphertext, a plaintext.
         */
        Plaintext decrypt(Ciphertext cipher1);

        // -------------------------- OPERATIONS ------------------------------
        // ADDITION
        /**
         * @brief Add second ciphertext to the first ciphertext.
         * @param[in,out] cipher1 First SEAL ciphertext.
         * @param[in] cipher2 Second SEAL ciphertext, to be added to the first.
         * @return Void.
         */
        void add(Ciphertext cipher1, Ciphertext cipher2);

        // MULTIPLICATION
        /**
         * @brief Multiply first ciphertext by the second ciphertext.
         * @param[in,out] cipher1 First SEAL Ciphertext.
         * @param[in] cipher2 Second SEAL Ciphertext , to be miltuplied to the first.
         * @return Void.
         */
        void mult(Ciphertext cipher1, Ciphertext cipher2);

        // SQUARE
        /**
         * @brief Square ciphertext values.
         * @param[in,out] cipher1 SEAL Ciphertext  whose values will get squared.
         * @return Void.
         */
        void square(Ciphertext cipher1);

        // NEGATE
        /**
        * @brief Negate values in a ciphertext
        * @param[in,out] c1  Ciphertext  whose values get negated.
        * @return Void.
        */
        void negate(Ciphertext cipher1);

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
         * @return pubKey the evaluation key.
         */
        PublicKey getevKey();

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
         * @brief Getter for flagVerbose, boolean to print info on terminal.
         * @return flagVerbose boolean to print info on terminal.
         */
        bool getflagVerbose();

        /**
         * @brief Getter for flagTime, boolean to print timings on terminal.
         * @return flagTime boolean to print timings on terminal.
         */
        bool getflagTime();

        //SETTERS
        /**
         * @brief Setter for publicKey, the key used to encrypt vectors.
         * @param[in] pubKey public key of the key pair.
         * @return Void.
         */
        void setpublicKey(PublicKey *pubKey);

        /**
         * @brief Setter for secretKey, the key used to decrypt vectors.
         * @param[in] secKey secret key of the key pair.
         * @return Void.
         */
        void setsecretKey(SecretKey *secKey);

        /**
         * @brief Getter for flagVerbose, boolean to print info on terminal.
         * @param[in] flagVerbose boolean to print info on terminal.
         * @return Void.
         */
        void setflagVerbose(bool flagV);

        /**
         * @brief Getter for flagTime, boolean to print timings on terminal.
         * @param[in] flagTime boolean to print timings on terminal.
         * @return Void.
         */
        void setflagVerbose(bool flagT);
};
#endif