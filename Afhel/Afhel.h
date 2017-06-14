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
#include <boost/unordered_map.hpp>
#include <boost/lexical_cast.hpp>
#include <sys/time.h>
#include <string.h>

#include "FHE.h"
#include "EncryptedArray.h"
#include "PAlgebra.h"


class Afhel{

    private:
        FHEcontext *context;                        // Required for key Generation
        FHESecKey *secretKey;                       // Secret key of the Public-Secret key pair
        FHEPubKey *publicKey;                       // Public key of the public-secret key pair
        EncryptedArray *ea;                         // Array used for encryption
        boost::unordered_map<string, Ctxt> ctxtMap; // Unordered map which stores the ciphertexts

        /**
        * @brief Store the ciphertext in the unordered map and return key where 
        * it was stored
        * @param ctxt Ciphertext to store in unordered map
        * @return the key used to locate this ciphertext in the unordered map
        */
        string store(Ctxt* ctxt);


    public:
        Afhel();
        virtual ~Afhel();
        
        bool flagPrint = false;                     // Flag to print messages on console
        long nslots;                                // Nº of slots in scheme
       
        /**
         * @brief Performs Key Generation using HElib functions
         * @param p plaintext base
         * @param r lifting 
         * @param c # of columns in key switching matrix
         * @param d degree of field extension
         * @param sec security parameter
         * @param w Hamming weight of secret key
         * @param L # of levels in modulus chain
         * @param m (optional parameter) use m'th cyclotomic polynomial
         * @param R (=3) number of expected rounds of multiplication
         * @param s (=0) minimum number of slots for vectors.
         * @param gens
         * @param ords
         */
        void keyGen(long p, long r, long c, long d, long sec, long w = 64,
                    long L = -1, long m = -1, long R = 3, long s = 0, 
                    const vector<long>& gens = vector<long>(),
                    const vector<long>& ords = vector<long>());

        /**
         * @brief Calls HElib encrypt function for provided plaintext vector and
         * then stores the ciphertext in the unordered map and returns the key
         * @param ptxt_vect plaintext vector to encrypt
         * @return ciphertext object
         */
        string encrypt(vector<long> ptxt_vect);
        
        /**
         * @brief Calls HElib decrypt function for ciphertext that is found in
         * unordered map at key
         * @param cyphertext to decrypt
         * @return the decrypted ciphertext
         */
        vector<long> decrypt(string key);
        
        /**
         * @brief Add ciphertext at key to ciphertext at other_key and store result
         * back in unordered map at key
         * @param key key in unordered map
         * @param other_key key in unordered map
         * @param negative if True then perform subtraction
         */
        void add(string k1, string k2, bool negative=false);
        
        /**
         * @breif Multiply ciphertext at key by ciphertext at other_key and store
         * result in unordered map at key
         * @param key key in unordered map
         * @param other_key key in unordered map
         */
        void mult(string k1, string k2);
        
        /**
         * @brief Multiply ciphertext by ciphertext and perform cumulative sum
         * @param key key in unordered map
         * @param other_key1 key in unordered map
         * @param other_key2 key in unordered map
         */
        void scalarProd(string k1, string k2);
        
        /**
         * @brief Square ciphertext at key
         * @param key key in unordered map
         */
        void square(string k1);

        /**
         * @brief Number of plaintext slots 
         * @return number of plaintext slots
         */
        long numSlots();

        /**
        * @brief Create a new ciphertext and set it equal to the ciphertext 
        * stored in unordered map under key
        * @param key ciphertext key in unordered map
        * @return key corresponding to new ciphertext
        */
        string set(string key);

        /**
        * @brief Retrieve the ciphertext object from the unordered map
        * @param key key in unordered map
        * @return the ciphertext corresponding to the passed in key
        */
        Ctxt retrieve(string key);
        
        /**
        * Replace the ciphertext at key with the new one provided
        * @param key key in unordered map
        * @param new_ctxt new Ctxt object to store in the unordered map
        */
        void replace(string key, Ctxt new_ctxt);
        
        /**
        * @brief Delete from the unordered map the entry at key
        * @param key key in unordered map
        */
        void erase(string key);

};

#endif
