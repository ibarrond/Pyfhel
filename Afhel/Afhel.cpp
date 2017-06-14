/*
 * Afhel
 * --------------------------------------------------------------------
 *  Afhel is a C++ library that creates an abstraction over the basic
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


#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <cassert>
#include <cstdio>

#include "Afhel.h"

using namespace std;

Afhel::Afhel(){}
Afhel::~Afhel(){}

void Afhel::keyGen(long p, long r, long c, long w, long d, long sec,
                       long L, long m, long R, long s,
                       const vector<long>& gens,
                       const vector<long>& ords){
    if(flagPrint){std::cout << "Afhel::keyGen START" << endl;}
    
    // Initializing possible empty parameters for context
    //  - L -> Heuristic computation
    if(L==-1){
        L=3*R+3;
        if(p>2 || r>1){
             L += R * 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
        }
        if(flagPrint){std::cout << "  - calculated L: " << L <<endl;}
    }
    //  - m -> use HElib method FindM with other parameters
    if(m==-1){
        m = FindM(sec, L, c, p, d, s, 0, 0);
        if(flagPrint){std::cout << "  - Calculated m: " << m <<endl;}
    }

    // Context creation
    context = new FHEcontext(m, p, r, gens, ords);  // Initialize context
    buildModChain(*context, L, c);                  // Add primes to modulus chain
    if(flagPrint){std::cout << "  - Created Context: " 
        << "p="   << p        << ", r=" << r
        << ", d=" << d        << ", c=" << c
        << ", sec=" << sec    << ", w=" << w
        << ", L=" << L        << ", m=" << m
        << ", gens=" << gens  << ", ords=" << ords <<  endl;}

    // ZZX Polynomial creation
    ZZX G;
    if (d == 0){  G = context->alMod.getFactorsOverZZ()[0];}
    else       {  G = makeIrredPoly(p, d);}
    if(flagPrint){std::cout << "  - Created ZZX poly from NTL lib" <<endl;}

    // Secret/Public key pair creation
    secretKey = new FHESecKey(*context);            // Initialize object
    publicKey = (FHEPubKey*) secretKey;             // Upcast: FHESecKey to FHEPubKey
    secretKey->GenSecKey(w);                        // Hamming-weight-w secret key
    if(flagPrint){std::cout << "  - Created Public/Private Key Pair" << endl;} 

    // Additional initializations
    addSome1DMatrices(*secretKey);                  // Key-switch matrices for relin.
    ea = new EncryptedArray(*context, G);           // Object for packing in subfields
    nslots = ea->size();


    if(flagPrint){std::cout << "Afhel::keyGen COMPLETED" << endl;}
}

string Afhel::encrypt(vector<long> plaintext) {
    Ctxt cyphertext(*publicKey);                    // Empty cyphertext object
    //TODO: create a vector of size nddSlots and fill it first with values from plaintext, then with zeros
    ea->encrypt(cyphertext, *publicKey, plaintext); // Encrypt plaintext
    string key = store(&cyphertext);
    if(flagPrint){
        std::cout << "  Afhel::encrypt({ID" << key << "}[" << plaintext <<  "])" << endl;
    }
    return key;
}

vector<long> Afhel::decrypt(string key) {
    vector<long> res(nslots, 0);                    // Empty vector of values
    ea->decrypt(ctxtMap.at(key), *secretKey, res);  // Decrypt cyphertext
    if(flagPrint){
        std::cout << "  Afhel::decrypt({ID" << key << "}[" << res << "])" << endl;
    }
    return res;
}

void Afhel::add(string k1, string k2, bool negative){
    ctxtMap.at(k1).addCtxt(ctxtMap.at(k2), negative);
    if(flagPrint){ std::cout << "  Afhel::add {ID" << k1 << "} + {ID" << k2 << "}" << endl;}
}

void Afhel::mult(string k1, string k2){
    ctxtMap.at(k1).multiplyBy(ctxtMap.at(k2));
    if(flagPrint){ std::cout << "  Afhel::mult {ID" << k1 << "} * {ID" << k2 << "}" <<endl;}
}

void Afhel::scalarProd(string k1, string k2){
    ctxtMap.at(k1).multiplyBy(ctxtMap.at(k2));
    totalSums(*ea, ctxtMap.at(k1));
    if(flagPrint){ std::cout << "  Afhel::scalarProd {ID" << k1 << "} @ {ID" << k2 << "}" <<endl;}
}

void Afhel::square(string k1){
    ctxtMap.at(k1).square();
    if(flagPrint){ std::cout << "  Afhel::square {ID" << k1 << "}" << endl;}
}

long Afhel::numSlots() {
    return ea->size();
}

string Afhel::store(Ctxt* ctxt) {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    string key = boost::lexical_cast<string>(ms);
    ctxtMap.insert(make_pair(key, *ctxt));
    return key;
}

string Afhel::set(string key){
    Ctxt ctxt = ctxtMap.at(key);
    return store(&ctxt);
}

Ctxt Afhel::retrieve(string key) {
    return ctxtMap.at(key);
}

void Afhel::replace(string key, Ctxt new_ctxt) {
    boost::unordered_map<string, Ctxt>::const_iterator i = ctxtMap.find(key);
    if(i != ctxtMap.end()) {
        ctxtMap.at(key) = new_ctxt;
    }
}

void Afhel::erase(string key) {
    if(ctxtMap.find(key) != ctxtMap.end()) {
        ctxtMap.erase(key);
    }
}

