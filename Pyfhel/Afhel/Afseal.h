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
 
#include <iostream>	/* Print in std::cout */
#include <string>	/* String class */
#include <vector>	/* Vectorizing all operations */
#include <thread>	/* memory pools, multithread*/
#include <memory>	/* Smart Pointers*/

#include <../SEAL/SEAL/seal/seal.h>

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
        
        shared_ptr<SEALContext> context=NULL;           /**< Context. Used for init*/
  
        shared_ptr<IntegerEncoder> intEncoder=NULL;     /**< Integer Encoding.*/
        shared_ptr<FractionalEncoder> fracEncoder=NULL; /**< Fractional Encoding.*/

        shared_ptr<KeyGenerator> keyGenObj=NULL;        /**< Key Generator Object.*/
        shared_ptr<SecretKey> secretKey=NULL;           /**< Secret key.*/
        shared_ptr<PublicKey> publicKey=NULL;           /**< Public key.*/
        shared_ptr<EvaluationKeys> relinKey=NULL;       /**< Relinearization object*/
        shared_ptr<GaloisKeys> rotateKeys=NULL;         /**< Galois key for batching*/

        shared_ptr<Encryptor> encryptor=NULL;           /**< Requires a Public Key.*/
        shared_ptr<Evaluator> evaluator=NULL;           /**< Requires a context.*/
        shared_ptr<Decryptor> decryptor=NULL;           /**< Requires a Secret Key.*/

        shared_ptr<PolyCRTBuilder> crtBuilder=NULL;     /**< Rotation in Batching. */


        long p;                          /**< All operations are modulo p^r */
        long m;                          /**< Cyclotomic index */

        long base;
        long sec;
        int intDigits;
        int fracDigits;
        
        bool flagBatch = false;         /**< Whether to use batching or not */



        // ------------------ STREAM OPERATORS OVERLOAD -----------------------
        /**
         * @brief An output stream operator, parsing the object into a string.
         * @param[out] outs output stream where to bulk the Afseal object
         * @param[in] af Afseal object to be exported
         * @see operator>>
         */
        friend ostream& operator<< (ostream& outs, Afseal const& af);

        /**
         * @brief An input stream operator, reading the parsed Afseal object 
         *        from a string stream.
         * @param[in] ins input stream where to extract the Afseal object
         * @param[out] af Afseal object to contain the parsed one
         * @see operator<<
         */
        friend istream& operator>> (istream& ins, Afseal const& af);



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
        Afseal &operator =(const Afseal &assign) = default;
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
        void ContextGen(long p, long m = 2048, bool flagBatching=false,
                        long base = 2, long sec=128, int intDigits = 64,
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
        /**
         * @brief Decrypts the ciphertext using secKey as secret key.
         * The decryption is carried out with SEAL.
         * @param[in] cipher1 a Ciphertext object from SEAL.
         * @return Plaintext the resulting of decrypting the ciphertext, a plaintext.
         */
        vector<int64_t> decrypt(Ciphertext& cipher1);
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
        vector<int64_t> decode(Plaintext& plain1);
		void decode(Plaintext& plain1, int64_t& valOut);
        void decode(Plaintext& plain1, double& valOut);
        void decode(Plaintext& plain1, vector<int64_t> &valueVOut);
        void decode(vector<Plaintext>& plain1, vector<int64_t> &valueVOut);
        void decode(vector<Plaintext>& plain1, vector<double> &valueVOut);


        // -------------------------- RELINEARIZATION -------------------------
        void rotateKeyGen(int& bitCount);
        void relinKeyGen(int& bitCount, int& size);
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
        void exponentiate(Ciphertext& cipher1, uint64_t& expon);
        void exponentiate(vector<Ciphertext>& cipherV, uint64_t& expon);
        void polyEval(Ciphertext& cipher1, vector<int64_t>& coeffPoly);
        void polyEval(Ciphertext& cipher1, vector<double>& coeffPoly);

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



        bool saverelinKey(string fileName);
        bool restorerelinKey(string fileName);

        bool saverotateKey(string fileName);
        bool restorerotateKey(string fileName);



        // ----------------------------- AUXILIARY ----------------------------
        bool batchEnabled();
        long relinBitCount();
        // GETTERS
        SecretKey getsecretKey(); 
        PublicKey getpublicKey();
        EvaluationKeys getrelinKey(); 
        GaloisKeys getrotateKeys();  
        int getnSlots();  
        int getp();
        int getm();
        int getbase();
        int getsec();
        int getintDigits();  
        int getfracDigits();  
        bool getflagBatch();   

        //SETTERS
        void setpublicKey(PublicKey& pubKey)
            {this->publicKey = make_shared<PublicKey> (pubKey);}
        void setsecretKey(SecretKey& secKey)
            {this->secretKey = make_shared<SecretKey> (secKey);}
        void setrelinKey(EvaluationKeys& relKey)
            {this->relinKey = make_shared<EvaluationKeys>(relKey);}

};
#endif
