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
        FHEcontext *context;
        FHESecKey *secretKey;
        FHEPubKey *publicKey;
        EncryptedArray *ea;
        /**
        * Unordered map which stores the ciphertexts
        */
        boost::unordered_map<string, Ctxt> ctxtMap;
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
        
        bool flagPrint = false;
        long nslots;   
       /**
         * @brief Performs Key Generation using HElib functions
         * @param p plaintext base
         * @param r lifting 
         * @param c # of columns in key switching matrix
         * @param w Hamming weight of secret key
         * @param d degree of field extension
         * @param sec security parameter
         * @param s (=0) minimum number of slots for vectors.
         * @param m (optional parameter) use m'th cyclotomic polynomial
         * @param L # of levels in modulus chain
         * @param R (=3) number of expected rounds of multiplication
         * @param gens 
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
