/**
 * @file Afpalisade.h
 *  --------------------------------------------------------------------
 * @brief Header of Afpalisade, library that creates an abstraction over basic
 *  functionalities of PALISADE as a Homomorphic Encryption library, such as
 *  addition, multiplication, scalar product and others.
 *
 *  Afhel implements a higher level of abstraction than HElib, and handles
 *  ciphertexts using an unordered map (key-value pairs) that is accessed
 *  via keys of type string. This is done in order to manage ciphertext
 *  using references (the keys), which will allow Pyfhel to work only
 *  using strings (keeping the ciphertexts in C++). Afhel also compresses
 *  the Context setup and Key generation into one single KeyGen function
 *  with multiple parameter selection.
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


#ifndef AFPALISADE_H
#define AFPALISADE_H

#include <iostream>
#include <fstream>
#include <random>
#include <iterator>
#include "palisade.h"
#include "cryptocontexthelper.h"
#include "utils/debug.h"
#include "encoding/encodings.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;


/**
* @brief Abstraction For PALISADE.
*
*  Afpalisade is a library that creates an abstraction over the basic
*  functionalities of PALISADE as a Homomorphic Encryption library, such as
*  addition, multiplication, scalar product and others.
*
*/
class Afpalisade{

    private:
        // -------------------------- ATTRIBUTES ----------------------------
        FHESecKey *secretKey;             /**< Secret key. Part of the key pair */
        FHEPubKey *publicKey;             /**< Public key. Part of the key pair */
        EncryptedArray *ea;               /**< HElib encrypted array. Used for operations (depends on context and publicKey) */
        ZZX G;                            /**< NTL Poly used to create ea */
        PlaintextModulus p = 2333;        /**< Modulo and exponent of ciphertext space. All operations are modulo p^r */
        usint m;                           /**< Cyclotomic index, determines Z_m^* */
        long nSlots;                      /**< Number of values that fit in a Ctxt. Can also be seen as the vectorization factor */
        bool flagVerbose = false;         /**< Flag to print messages on console */
        bool flagTime = false;            /**< Flag to print timings on console */

        // ------------------ STREAM OPERATORS OVERLOAD ----------------------
        /**
         * @brief An output stream operator, parsing the object into a string.
         * @param[out] outs output stream where to bulk the Afhel object
         * @param[in] af Afhel object to be exported
         * @see operator>>
         */
        friend std::ostream& operator<< (std::ostream& outs, Afhel const& af);

        /**
         * @brief An input stream operator, reading the parsed Afhel object from a string.
         * @param[in] ins input stream where to extract the Afhel object
         * @param[out] af Afhel object to contain the parsed one
         * @see operator<<
         */
        friend std::istream& operator>> (std::istream& ins, Afhel& af);



    public:
        // ----------------------- CLASS MANAGEMENT --------------------------
        /**
         * @brief Default constructor.
         */
        Afpalisade();

        /**
         * @brief Copy constructor.
         * @param[in] otherAfhel Afhel object to be copied
         */
        Afhel(Afhel const& otherAfhel);

        /**
        * @brief Default destructor.
        */
        virtual ~Afhel();


        // -------------------------- CRYPTOGRAPHY ---------------------------
        // CONTEXT GENERATION
        /**
         * @brief Performs generation of FHE context using HElib functions.
         *          As a result, context, ea and nSlots are initialized.
         * @param[in] p ciphertext space base.
         * @param[in] r ciphertext space lifting .
         * @param[in] m (optional) use m'th cyclotomic polynomial. Default set by heuristics (-1)
         * @param[in] L (optional) # of levels in modulus chain.
                            Default set by heuristics on R and r (0). If set, overrides R.
         * @param[in] R (optional) # of expected rounds of mult. Default 3.
         * @param[in] sec (optional) security parameter. Default is  80.
         * @param[in] w (optional) Hamming weight of secret key. Default is 64.
         * @param[in] c (optional) # of columns in key switching matrix. Default 2. Typ 2-4.
         * @param[in] d (optional) degree of field extension. Default unset (0).
         * @return Void.
         */
        void ContextGen(long p, long r, long m = -1, bool isBootstrappable = false,
                        long L = -1, long R = 3, long sec, long c = 2, long d = 0);

        // KEY GENERATION
        /**
         * @brief Performs Key generation using HElib functions vased on current context.
         *          As a result, a pair of Private/Public Keys are initialized and stored.
         * @param[in] w Hamming weight of secret key. Default is 64 bits.
         * @return Void.
         */
        void KeyGen(long w=64);

        // ENCRYPTION
        /**
         * @brief Enctypts a provided plaintext vector using pubKey as public key.
         *      The encryption is carried out with HElib.
         * @param[in] ptxt_vect plaintext vector to encrypt.
         * @param[in] pubKey the public key to be used. Default is publicKey, attribute of Afhel.
         * @return ciphertext the HElib encrypted ciphertext.
         */
        Ctxt encrypt(vector<long> ptxt_vect, FHEPubKey& pubKey=this.publicKey);

        // DECRYPTION
        /**
         * @brief Decrypts the ciphertext using secKey as secret key.
         * The decryption is carried out with HElib.
         * @param[in] ciphertext a Ctxt object from HElib.
         * @param[in] secKey the secret key to be used. Default is secretKey, attribute of Afhel.
         * @return vector<long> the resulting of decrypting the ciphertext, a plaintext.
         */
        vector<long> decrypt(Ctxt ciphertext, FHESecKey& secKey=this.secretKey);

        // -------------------------- OPERATIONS ------------------------------
        // ADDITION
        /**
         * @brief Add second ciphertext to the first ciphertext.
         * @param[in,out] c1 First HElib Ctxt ciphertext.
         * @param[in] c2 Second HElib Ctxt ciphertext, to be added to the first.
         * @param[in] negative if True then perform subtraction.
         * @return Void.
         */
        void add(Ctxt c1, Ctxt c2, bool negative=false);

        // MULTIPLICATION
        /**
         * @brief Multiply first ciphertext by the second ciphertext.
         * @param[in,out] c1 First HElib Ctxt ciphertext.
         * @param[in] c2 Second HElib Ctxt ciphertext, to be miltuplied to the first.
         * @return Void.
         */
        void mult(Ctxt c1, Ctxt c2);

        /**
         * @brief Multiply first ciphertext by the second and third ciphertexts.
         * @param[in,out] c1 First HElib Ctxt ciphertext.
         * @param[in] c2 Second HElib Ctxt ciphertext, to be miltuplied to the first.
         * @param[in] c3 Third HElib Ctxt ciphertext, to be miltuplied to the first.
         * @return Void.
         */
        void mult3(Ctxt c1, Ctxt c2, Ctxt c3);

        // CUMULATIVE SUM
        /**
         * @brief Sum all the values in the vector.
         * As a result, all the slots inside the ciphertext will contain the sum.
         * It is recommended to use instead your own algorithm using addition and rotation.
         * @param c1 Ciphertext where the cumsum will happen.
         * @return Void.
         */
        void cumSum(Ctxt c1);

        // SCALAR PRODUCT
        /**
         * @brief Multiply ciphertext by ciphertext and perform cumulative sum
         * @param[in,out] c1 First HElib Ctxt ciphertext, where cumsum and mult will happen.
         * @param[in] c2 Second HElib Ctxt ciphertext, to be miltuplied to the first.
         * @return Void.
         */
         void scalarProd(Ctxt c1, Ctxt c2, int partitionSize=0);


        // SQUARE
        /**
         * @brief Square ciphertext values.
         * @param[in,out] c1 HElib Ctxt ciphertext whose values will get squared.
         * @return Void.
         */
        void square(Ctxt c1);

        // CUBE
        /**
         * @brief Raise to cube the ciphertext values.
         * @param[in,out] c1 HElib Ctxt ciphertext whose values will get cubed.
         * @return Void.
         */
        void cube(Ctxt c1);

        // NEGATE
        /**
        * @brief Negate values in a ciphertext
        * @param[in,out] c1 HElib Ctxt ciphertext whose values get negated.
        * @return Void.
        */
        void negate(Ctxt c1);

        // COMPARE EQUALS
        /**
         * @brief Compare ciphertext c1 and ciphertext c2.
         * @param[in] c1 HElib Ctxt ciphertext.
         * @param[in] c2 HElib Ctxt ciphertext.
         * @param[in] comparePkeys if true then keys will be compared.
         * @return BOOL with the comparison c1 == c2
         */
        bool equalsTo(Ctxt c1, Ctxt c2, bool comparePkeys=true);

        // ROTATE
        /**
         * @brief Rotate ciphertext by c spaces.
         * Overflowing values are added at the other side
         * @param[in,out] c1 HElib Ctxt ciphertext whose values get rotated.
         * @param[in] c number of spaces to rotate
         * @return Void.
         */
        void rotate(Ctxt c1, long c);

        // SHIFT
        /**
         * @brief Rotate ciphertext by c spaces.
         * Overflowing values are added at the other side
         * @param[in,out] c1 HElib Ctxt ciphertext whose values get rotated.
         * @param[in] c number of spaces to rotate
         * @return Void.
         */
        void shift(Ctxt c1, long c);

        // POLYNOMIALS.
        /**
         * @brief Create ZZX polynomial using coefficients.
         * @param[in] coeffPoly Vector of long coefficients for the polynomial
         * @return ZZXpoly polynomial object with coefficients.
         */
        ZZX createPolynomeWithCoeff(vector<long> const& coeffPoly);

        /**
         * @brief Compute polynomial over a cyphertext
         * @param[in] coeffPoly Vector of long coefficients for the polynomial
         * @param[in,out] c1 HElib Ctxt ciphertext whose values get applied the polynomial.
         * @return void.
         */
        void polyEval(Ctxt c1, vector<long> const& coeffPoly);


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
        FHESecKey getsecretKey();

        /**
         * @brief Getter for for publicKey, the key used to encrypt vectors.
         * @return pubKey the public key of the key pair.
         */
        FHEPubKey getpublicKey();

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
         * @brief get the whole cyphertext space size, p^r
         * @return p2r p^r, cyphertext space size
         */
        long getp2r() const;

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
        void setpublicKey(FHEPubKey *pubKey);

        /**
         * @brief Setter for secretKey, the key used to decrypt vectors.
         * @param[in] secKey secret key of the key pair.
         * @return Void.
         */
        void setsecretKey(FHESecKey *secKey);

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
