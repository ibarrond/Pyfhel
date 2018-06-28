
/**
 * @file Afpalisade.cpp
 * --------------------------------------------------------------------
 * @brief Afhel is a C++ library that creates an abstraction over the basic
 *  functionalities of HElib as a Homomorphic Encryption library, such as
 *  addition, multiplication, scalar product and others.
 *
 *  This is the implementation file. Refer to the .h file for a well
 *  documented API ready to use.
 *  --------------------------------------------------------------------
 * @author Alberto Ibarrondo (ibarrond)
 *  --------------------------------------------------------------------
  * @bugs No known bugs
 */

 /*  License: GNU GPL v3
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

#include <math.h>       /* pow */
#include <fstream>      /* file management */

#include "Afhel.h"

using namespace std;

// ----------------------- CLASS MANAGEMENT --------------------------
Afhel::Afhel(){}

Afhel::Afhel(Afhel const& otherAfhel){
    this.secretKey =    new FHESecKey(*(otherAfhel.secretKey));
    this.publicKey =    new FHEPubKey(*(otherAfhel.publicKey));
    this.ea =           new EncryptedArray(*(otherAfhel.ea));
    this.m =            otherAfhel.getm();
    this.p =            otherAfhel.getp();
    this.r =            otherAfhel.getr();
    this.nSlots =       otherAfhel.getnSlots();
    this.flagVerbose =  otherAfhel.getflagVerbose();
    this.flagTime =     otherAfhel.getflagTime();
}

Afhel::~Afhel(){}

// ------------------------------ CRYPTOGRAPHY --------------------------------
// CONTEXT GENERATION
void Afhel::ContextGen(long p, long r, long m, bool isBootstrappable,
                       long L, long R, long sec, long c, long d){

    if(flagVerbose){std::cout << "Afhel::ContextGen START" << endl;}

    // Initializing possible empty parameters for context
    //  - L -> Heuristic computation (requires R)
    if(L==-1){
        L=3*R+3;
        if(p>2 || r>1){
             L += R * 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
        }
        if(flagVerbose){std::cout << "  - Heuristic L: " << L <<endl;}
    }
    //  - m -> use HElib method FindM with other parameters
    if(m==-1){
        m = FindM(sec, L, c, p, d, 0, 0);
        if(flagVerbose){std::cout << "  - Heuristic m: " << m <<endl;}
    }

    // Context creation
    this.p = p;
    this.r = r;
    FHEcontext *context = new FHEcontext(m, p, r);           // Initialize context
    buildModChain(*context, L, c);                          // Add primes to modulus chain
    if(flagVerbose){std::cout << "  - Created Context: "
        << "p="   << p        << ", r=" << r
        << ", d=" << d        << ", c=" << c
        << ", sec=" << sec    << ", w=" << w
        << ", L=" << L        << ", m=" << m <<  endl;}

    // ZZX Polynomial creation
    if (d == 0){  G = context->alMod.getFactorsOverZZ()[0];}
    else       {  G = makeIrredPoly(p, d);}
    if(flagVerbose){std::cout << "  - Created ZZX poly used for EncryptedArray" <<endl;}

    // Additional initializations
    this.ea = new EncryptedArray(*context, G);           // Object for operations
    this.nSlots = ea->size();                            // Maximum SIMD vector size
    if(flagVerbose){std::cout << "  - Created EncryptedArray" <<endl;}
    if(flagVerbose){std::cout << "Afhel::ContextGen COMPLETED" << endl;}
}

// KEY GENERATION
void Afhel::KeyGen(long w){
    if(flagVerbose){std::cout << "Afhel::keyGen START" << endl;}
    // Secret/Public key pair creation
    this.secretKey = new FHESecKey(ea->context);         // Initialize object using context
    this.publicKey = (FHEPubKey*) secretKey;             // Upcast: FHESecKey to FHEPubKey
    this.secretKey->GenSecKey(w);                        // Hamming-weight-w secret key
    addSome1DMatrices(*secretKey);                       // Key-switch matrices
    if(flagVerbose){std::cout << "Afhel::keyGen COMPLETED" << endl;}
}

// ENCRYPTION
Ctxt Afhel::encrypt(vector<long> plaintext, FHEPubKey *pubKey) {
        Ctxt ciphertext(*pubKey);                    // Empty ciphertext object
        //TODO: create a vector of size nddSlots and fill it first with values from plaintext, then with zeros
        ea->encrypt(ciphertext, *pubKey, plaintext); // Encrypt plaintext

        if(flagVerbose){
            std::cout << "  Afhel::encrypt({ID" << id1 << "}[" << plaintext <<  "])" << endl;
        }
        return ciphertext;
}

// DECRYPTION
vector<long> Afhel::decrypt(Ctxt ciphertext) {
        vector<long> res(nslots, 0);                    // Empty vector of values
        ea->decrypt(ctxtMap.at(id1), *secretKey, res);  // Decrypt ciphertext
        if(flagVerbose){
            std::cout << "  Afhel::decrypt({ID" << id1 << "}[" << res << "])" << endl;
        }
        return res;
}

// ENCODING
NewPlaintextArray Afhel::encode(vector<long> plaintext) {
        NewPlaintextArray ptxtArr(ea)                  // Empty plaintext object
        ea->encode(ptxtArr, plaintext)                 // Encode using ea
        if(flagVerbose){
            std::cout << "  Afhel::encode([" << plaintext <<  "])" << endl;
        }
        return ptxtArr;
}

// DECODING
vector<long> Afhel::decode(NewPlaintextArray& ptxtArr) {
        vector<long> res(nslots, 0);                    // Empty vector of values
        ea->decrypt(ptxtArr, res);                      // Decode using ea
        if(flagVerbose){
            std::cout << "  Afhel::decode([" << res << "])" << endl;
        }
        return res;
}

// ------------------------------------- I/O ----------------------------------
// SAVE CONTEXT
bool Afhel::saveContext(string fileName){
    bool res=1;
    try{
        fstream keyFile(fileName+".aenv", fstream::out|fstream::trunc);
        assert(keyFile.is_open());

        writeContextBase(keyFile, ea->getContext());// Write m, p, r, gens, ords
        keyFile << ea->getContext();                // Write the rest of the context
        keyFile << G;                               // Write G poly (ea can't be written, we save
                                                    //  G in order to reconstruct ea in restoreContext)
        keyFile.close();
    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

// RESTORE CONTEXT
bool Afhel::restoreContext(string fileName){
    bool res=1;
    long m1, p1, r1;
    vector<long> gens, ords;

    try{

        fstream keyFile(fileName+".aenv", fstream::in);
        assert(keyFile.is_open());

        readContextBase(keyFile, m1, p1, r1, gens, ords);   // Read m, p, r, gens, ords
        context = new FHEcontext(m1, p1, r1, gens, ords);   // Initialize context
        keyFile >> *context;                                // Read the rest of the context
        keyFile >> G;                                       // Read G Poly

        keyFile.close();

        ea = new EncryptedArray(*context, G);        // Reconstruct ea using G and context
        this.nSlots = ea->size();                    // Refill nslots
        this.p = p1;
        this.r = r1;
    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}



// ----------------------------- AUXILIARY ----------------------------
// GETTERS
FHESecKey getsecretKey()	{return this.secretKey;}
FHEPubKey getpublicKey()	{return this.publicKey;}
long Afhel::getnSlots()     {this.nSlots = ea->size(); return this.nSlots;}
long Afhel::getm()          {return this.m;}
long Afhel::getp()          {return this.p;}
long Afhel::getr()          {return this.r;}
long Afhel::getp2r() const  {return this.ea.getAlMod().getPPowR()}
bool Afhel::getflagVerbose(){return this.flagVerbose;}
bool Afhel::getflagTime()   {return this.flagTime;}

// SETTERS
void setpublicKey(FHEPubKey& pubKey)   	{this.publicKey = pubKey;}
void setsecretKey(FHESecKey& secKey)	{this.secretKey = secKey}
void Afhel::setflagVerbose(bool flagV) 	{this.flagVerbose = flagV;}
void Afhel::setflagVerbose(bool flagT) 	{this.flagTime = flagT;}
