/*
 *  Afhel
 *  --------------------------------------------------------------------
 *  Afhel is a library that creates an abstraction over the basic
 *  functionalities of HElib as a Homomorphic Encryption library, such as
 *  addition, multiplication, scalar product and others.
 *
 *  Afhel implements a higher level of abstraction than HElib, and handles
 *  Cyphertexts using an unordered map (key-value pairs) that is accessed
 *  via keys of type string. This is done in order to manage Cyphertext 
 *  using references (the keys), which will allow Pyfhel to work only 
 *  using strings (keeping the Cyphertexts in C++). Afhel also compresses
 *  the Context setup and Key generation into one single KeyGen function
 *  with multiple parameter selection.
 *  --------------------------------------------------------------------
 *  Author: Alberto Ibarrondo
 *  Date: 14/06/2017  
 *  --------------------------------------------------------------------
 *  License: GNU GPL v3
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
 *  --------------------------------------------------------------------
 */


#ifndef ALFHEL_H
#define ALFHEL_H

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <sys/time.h>
#include <string.h>

#include <boost/unordered_map.hpp>
#include <boost/lexical_cast.hpp>

#include "FHE.h"
#include "EncryptedArray.h"
#include "PAlgebra.h"


class Afhel{

    private:
        FHEcontext *context;                        // Required for key Generation
        FHESecKey *secretKey;                       // Secret key of the Public-Secret key pair
        FHEPubKey *publicKey;                       // Public key of the public-secret key pair
        ZZX G;                                      // NTL Poly used to create ea
        EncryptedArray *ea;                         // Array used for encryption
        boost::unordered_map<string, Ctxt> ctxtMap; // Unordered map which stores the ciphertexts
        /**
        * @brief Store the ciphertext in the unordered map and return key where 
        * it was stored
        * @param ctxt Ciphertext to store in unordered map
        * @return the ID used to locate this ciphertext in the unordered map
        */
        string store(Ctxt* ctxt);


    public:
        Afhel();
        virtual ~Afhel();
        
        bool flagPrint = false;                     // Flag to print messages on console
        long nslots;                                // Nº of slots in scheme

        // -------------------------- CRYPTOGRAPHY ----------------------------
        // KEY GENERATION
        /**
         * @brief Performs Key Generation using HElib functions
         * @param p plaintext base
         * @param r lifting 
         * @param c # of columns in key switching matrix
         * @param d degree of field extension
         * @param sec security parameter
         * @param w Hamming weight of secret key
         * @param L # of levels in modulus chain
         * @param m (optional) use m'th cyclotomic polynomial
         * @param R (=3) number of expected rounds of multiplication
         * @param s (=0) minimum number of slots for vectors.
         * @param gens (optional) Vector of Generators
         * @param ords (optional) Vector of Orders
         */
        void keyGen(long p, long r, long c, long d, long sec, long w = 64,
                    long L = -1, long m = -1, long R = 3, long s = 0, 
                    const vector<long>& gens = vector<long>(),
                    const vector<long>& ords = vector<long>());

        // ENCRYPTION
        /**
         * @brief Enctypts a provided plaintext vector and stores the cyphertext
         * in the unordered map, returning the key(string) used to access it.
         * The encryption is carried out with HElib. 
         * @param ptxt_vect plaintext vector to encrypt
         * @return id (string) used to access ciphertext in the ctxtMap.
         */
        string encrypt(vector<long> ptxt_vect);
        
        // DECRYPTION
        /**
         * @brief Decrypts the cyphertext accessed in the ctxtMap using the id.
         * The decryption is carried out with HElib.
         * @param id (string) used to access ciphertext in the ctxtMap.
         * @return plaintext, the result of decrypting the ciphertext
         */
        vector<long> decrypt(string id1);
        
        // -------------------------- OPERATIONS ------------------------------
        // ADDITION
        /**
         * @brief Add ciphertext at key to ciphertext at other_key and store result
         * back in unordered map at key
         * @param id1 ID of ctxt1 in unordered map
         * @param id2 ID of ctxt2 in unordered map
         * @param negative if True then perform subtraction
         */
        void add(string id1, string id2, bool negative=false);
        
        // MULTIPLICATION
        /**
         * @breif Multiply ciphertext at key by ciphertext at other_key and store
         * result in unordered map at key
         * @param id1 ID of ctxt 1 in unordered map
         * @param id2 ID of ctxt 2 in unordered map
         * @param id3 ID of ctxt 3 in unordered map
         */
        void mult(string id1, string id2);
        void mult3(string id1, string id2, string id3);

        // SCALAR PRODUCT
        /**
         * @brief Multiply ciphertext by ciphertext and perform cumulative sum
         * @param id1 ID of ctxt1 in unordered map
         * @param id2 ID of ctxt2 in unordered map
         */
        void scalarProd(string id1, string id2, int partitionSize=0);
        
        // SQUARE
        /**
         * @brief Square ciphertext at id1 in ctxtMap
         * @param id1 ID of ctxt in unordered map
         */
        void square(string id1);

        // CUBE
        /**
         * @brief Cube ciphertext at id1 in ctxtMap
         * @param id1 ID of ctxt in unordered map
         */
        void cube(string id1);

        // NEGATE
        /**
        * @brief Multiply ciphertext at id1 by -1
        * @param id1 ID of ctxt in unordered map ctxtMap
        */
        void negate(string id1);
        
        // COMPARE EQUALS
        /**
        * @brief Compare ciphertext at id1 and ciphertext at id2 
        * to see if they are equal
        * @param id1 ID of ctxt 1 in unordered map ctxtMap
        * @param id2 ID of ctxt 2 in unordered map ctxtMap
        * @param comparePkeys if true then pkeys will be compared
        * @return BOOL --> ctxt(id1) == ctxt(id2)
        */
        bool equalsTo(string id1, string id2, bool comparePkeys=true);

        // ROTATE
        /**
        * @brief Rotate ciphertext at id1 by c spaces
        * @param id1 ID of ctxt in unordered map ctxtMap
        * @param c number of spaces to rotate
        */
        void rotate(string id1, long c);
        
        // SHIFT
        /**
        * @brief Shift ciphertext at id1 by c spaces
        * @param id1 ID of ctxt in unordered map ctxtMap
        * @param c number of spaces to shift
        */
        void shift(string id1, long c);

        
        // -------------------------------- I/O -------------------------------
        // SAVE ENVIRONMENT
        /**
         * @brief Saves the context, SecretKey and G polynomial in a .aenv file
         * @param fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool saveEnv(string fileName);

        // RESTORE ENVIRONMENT
        /**
         * @brief Restores the context, SecretKey and G polynomial from a .aenv file.
         *  Then it reconstucts publicKey and ea (EncriptedArray) with SecretKey & G.
         * @param fileName name of the file without the extention
         * @return BOOL 1 if all ok, 0 otherwise
         */
        bool restoreEnv(string fileName);


        // ----------------------------- AUXILIARY ----------------------------
        /**
         * @brief Number of plaintext slots 
         * @return number of plaintext slots
         */
        long numSlots();

        /**
        * @brief Create a new ciphertext and set it equal to the ciphertext 
        * stored in unordered map under ID id1
        * @param id1 ID of ctxt in unordered map ctxtMap
        * @return ID corresponding to new ciphertext
        */
        string set(string id1);

        /**
        * @brief Retrieve the ciphertext object from the unordered map
        * @param id1 ID of ctxt in unordered map ctxtMap
        * @return the ciphertext corresponding to the one stored with ID id1
        */
        Ctxt retrieve(string id1);
        
        /**
        * Replace the ciphertext at id1 with the new one provided
        * @param id1 ID of ctxt in unordered map ctxtMap
        * @param new_ctxt new Ctxt object to store in the unordered map
        */
        void replace(string id1, Ctxt new_ctxt);
        
        /**
        * @brief Delete from the unordered map the entry at key
        * @param id1 ID of ctxt in unordered map ctxtMap
        */
        void erase(string id1);

};

#endif
