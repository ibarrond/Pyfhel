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
 *  Afhel is free software: you can redistribute it and/or modify
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


#include <cstdio>
#include <fstream>
#include <iostream>
#include <cstddef>
#include <sys/time.h>

#include <FHE.h>
#include <timing.h>
#include <EncryptedArray.h>
#include "Afhel.h"

using namespace std;

Afhel::Afhel(){}
Afhel::~Afhel(){}

// ------------------------------ CRYPTOGRAPHY --------------------------------
// KEY GENERATION
void Afhel::keyGen(long p, long r, long c, long d, long sec, long w,
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
            m = FindM(sec, L, c, p, d, 0, 0);
            if(flagPrint){std::cout << "  - Calculated m: " << m <<endl;}
        }

        // Context creation
        global_m = m;
        global_p = p;
        global_r = r;
        context = new FHEcontext(m, p, r, gens, ords);  // Initialize context
        buildModChain(*context, L, c);                  // Add primes to modulus chain
        if(flagPrint){std::cout << "  - Created Context: " 
            << "p="   << p        << ", r=" << r
            << ", d=" << d        << ", c=" << c
            << ", sec=" << sec    << ", w=" << w
            << ", L=" << L        << ", m=" << m
            << ", gens=" << gens  << ", ords=" << ords <<  endl;}

        // ZZX Polynomial creation
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

// ENCRYPTION
string Afhel::encrypt(vector<long> plaintext) {
        Ctxt cyphertext(*publicKey);                    // Empty cyphertext object
        //TODO: create a vector of size nddSlots and fill it first with values from plaintext, then with zeros
        ea->encrypt(cyphertext, *publicKey, plaintext); // Encrypt plaintext
        string id1 = store(&cyphertext);
        if(flagPrint){
            std::cout << "  Afhel::encrypt({ID" << id1 << "}[" << plaintext <<  "])" << endl;
        }
        return id1;
}

// DECRYPTION
vector<long> Afhel::decrypt(string id1) {
        vector<long> res(nslots, 0);                    // Empty vector of values
        ea->decrypt(ctxtMap.at(id1), *secretKey, res);  // Decrypt cyphertext
        if(flagPrint){
            std::cout << "  Afhel::decrypt({ID" << id1 << "}[" << res << "])" << endl;
        }
        return res;
}


// ---------------------------- OPERATIONS ------------------------------------
// ADDITION
void Afhel::add(string id1, string id2, bool negative){
        ctxtMap.at(id1).addCtxt(ctxtMap.at(id2), negative);
}

// MULTIPLICATION
void Afhel::mult(string id1, string id2){
        ctxtMap.at(id1).multiplyBy(ctxtMap.at(id2));
}

// MULTIPLICATION BY 2
void Afhel::mult3(string id1, string id2, string id3){
        ctxtMap.at(id1).multiplyBy2(ctxtMap.at(id2), ctxtMap.at(id3));
}

// SCALAR PRODUCT
void Afhel::scalarProd(string id1, string id2, int partitionSize){
        ctxtMap.at(id1).multiplyBy(ctxtMap.at(id2));
        totalSums(*ea, ctxtMap.at(id1));
}

// CUMULATIVE SUM
void Afhel::cumSum(string id1){
        totalSums(*ea, ctxtMap.at(id1));
}

// SQUARE
void Afhel::square(string id1){
        ctxtMap.at(id1).square();
}

// CUBE
void Afhel::cube(string id1){
        ctxtMap.at(id1).cube();
}

// NEGATE
void Afhel::negate(string id1){
        ctxtMap.at(id1).negate();
}

// COMPARE EQUALS
bool Afhel::equalsTo(string id1, string id2, bool comparePkeys){
        return ctxtMap.at(id1).equalsTo(ctxtMap.at(id2), comparePkeys);
}

// ROTATE
void Afhel::rotate(string id1, long c){
        ea->rotate(ctxtMap.at(id1), c);
}

// SHIFT
void Afhel::shift(string id1, long c){
        ea->shift(ctxtMap.at(id1), c);
}


// ------------------------------------- I/O ----------------------------------
// SAVE ENVIRONMENT
bool Afhel::saveEnv(string fileName){
    bool res=1;
    try{
        fstream keyFile(fileName+".aenv", fstream::out|fstream::trunc);
        assert(keyFile.is_open());

        writeContextBase(keyFile, *context);    // Write m, p, r, gens, ords
        keyFile << *context << endl;            // Write the rest of the context
        keyFile << *secretKey << endl;          // Write Secret key
        keyFile << G <<endl;                    // Write G poly (ea can't be written, we save
                                                //  G in order to reconstruct ea in restoreEnv)
        keyFile.close();
    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

// RESTORE ENVIRONMENT
bool Afhel::restoreEnv(string fileName){
    bool res=1;
    unsigned long m1, p1, r1;
    vector<long> gens, ords;
    try{
        fstream keyFile(fileName+".aenv", fstream::in);
        assert(keyFile.is_open());

        readContextBase(keyFile, m1, p1, r1, gens, ords);   
                                                            // Read m, p, r, gens, ords
        context = new FHEcontext(m1, p1, r1, gens, ords);   
                                                            // Prepare empty context object
        secretKey = new FHESecKey(*context);                // Prepare empty FHESecKey object
        
        keyFile >> *context;                    // Read the rest of the context
        keyFile >> *secretKey;                  // Read Secret Key
        keyFile >> G;                           // Read G Poly
        ea = new EncryptedArray(*context, G);   // Reconstruct ea using G
        publicKey = (FHEPubKey*) secretKey;     // Reconstruct Public Key from Secret Key
        nslots = ea->size();                    // Refill nslots
        global_m = m1;
        global_p = p1; 
        global_r = r1;
    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}


// --------------------------------- AUXILIARY --------------------------------

long Afhel::numSlots() {
    return ea->size();
}

long Afhel::getM(){ return global_m; }
long Afhel::getP(){ return global_p; }
long Afhel::getR(){ return global_r; }

string Afhel::store(Ctxt* ctxt) {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    string id1 = boost::lexical_cast<string>(ms);
    ctxtMap.insert(make_pair(id1, *ctxt));
    return id1;
}

string Afhel::set(string id1){
    Ctxt ctxt = ctxtMap.at(id1);
    return store(&ctxt);
}

Ctxt Afhel::retrieve(string id1) {
    return ctxtMap.at(id1);
}

void Afhel::replace(string id1, Ctxt new_ctxt) {
    boost::unordered_map<string, Ctxt>::const_iterator i = ctxtMap.find(id1);
    if(i != ctxtMap.end()) {
        ctxtMap.at(id1) = new_ctxt;
    }
}

void Afhel::erase(string id1) {
    if(ctxtMap.find(id1) != ctxtMap.end()) {
        ctxtMap.erase(id1);
    }
}

// AUXILIARY TIMER FUNCTION FOR TESTS

Timer::Timer(bool print){flagPrint=print;}
Timer::~Timer(){}

void Timer::start() { this->m_start = my_clock();}
void Timer::stop()  { this->m_stop = my_clock(); }
double Timer::elapsed_time() {
double dt = this->m_stop - this->m_start;
    if(flagPrint){std::cout << "Elapsed time: " << dt << endl;}
    return dt;      }
double Timer::my_clock() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;}

