
/**
 * @file Afseal.cpp
 * --------------------------------------------------------------------
 * @brief Afseal is a C++ library that creates an abstraction over the basic
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
  *  Afseal is free software: you can redistribute it and/or modify
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

#include "Afseal.h"

using namespace std;

// ----------------------------- CLASS MANAGEMENT -----------------------------
Afseal::Afseal(){}

Afseal::Afseal(Afseal &otherAfseal){
    this->secretKey =    new SecretKey(otherAfseal.getsecretKey());
    this->publicKey =    new PublicKey(otherAfseal.getpublicKey());
    this->m =            otherAfseal.getm();
    this->p =            otherAfseal.getp();
    this->r =            otherAfseal.getr();
    this->flagTime =     otherAfseal.getflagTime();
}

Afseal::~Afseal(){}

// ------------------------------ CRYPTOGRAPHY --------------------------------
// GENERATION
void Afseal::ContextGen(long p, long r, long m){

    EncryptionParameters parms;

    // m - cyclotomic polynomial exponent, must be power 2 in FV scheme
    bool m_is_pow2 = false;
    for (float i = 10; i < 30; i++) {
      if((float)(m)==pow(2, i)){m_is_pow2 = true;}}
    if(!m_is_pow2){throw std::invalid_argument("m must be power of 2 in SEAL");}

    // Context generation
    parms.set_poly_modulus("1x^"+std::to_string(m)+" + 1");
    parms.set_coeff_modulus(coeff_modulus_128(m));
    parms.set_plain_modulus(1 << p);
    this->context = new SEALContext(parms);

    // Create Evaluator Key
    this->evaluator=new Evaluator(*context);
}

void Afseal::KeyGen(){
    this->keyGenObj = new KeyGenerator(*context);
    this->publicKey = new PublicKey(keyGenObj->public_key());   // Extract keys
    this->secretKey = new SecretKey(keyGenObj->secret_key());

    this->encryptor=new Encryptor(*context, *publicKey); // encr/decr objs
    this->decryptor=new Decryptor(*context, *secretKey);
}

// ENCRYPTION
Ciphertext Afseal::encrypt(Plaintext& plain1) {
    Ciphertext cipher1;
    encryptor->encrypt(plain1, cipher1);
    return cipher1;
    }
Ciphertext Afseal::encrypt(double& value1) {
    Ciphertext cipher1;
    encryptor->encrypt(fracEncoder->encode(value1), cipher1);
    return cipher1;
    }
Ciphertext Afseal::encrypt(int& value1) {
    Ciphertext cipher1;
    encryptor->encrypt(intEncoder->encode(value1), cipher1);
    return cipher1;
    }
void Afseal::encrypt(Plaintext& plain1, Ciphertext& cipher1) {
    encryptor->encrypt(plain1, cipher1);
    }
void Afseal::encrypt(double& value1, Ciphertext& cipher1) {
    encryptor->encrypt(fracEncoder->encode(value1), cipher1);
    }
void Afseal::encrypt(int& value1, Ciphertext& cipher1) {
    encryptor->encrypt(intEncoder->encode(value1), cipher1);
    }

//DECRYPTION
Plaintext Afseal::decrypt(Ciphertext& cipher1) {
    Plaintext plain1; 
    decryptor->decrypt(cipher1, plain1);
    return plain1;
    }
void Afseal::decrypt(Ciphertext& cipher1, Plaintext& plain1) {
    decryptor->decrypt(cipher1, plain1);
    }
void Afseal::decrypt(Ciphertext& cipher1, int& value1) {
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    value1 = fracEncoder->decode(plain1);
    }
void Afseal::decrypt(Ciphertext& cipher1, double& value1) {
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    }

// -------------------------------- ENCODING ----------------------------------

Plaintext Afseal::encode(int& value1) {
    Plaintext plain1 = intEncoder->encode(value1);
    return plain1;
}

Plaintext Afseal::encode(double value1) {
Plaintext plain1 = fracEncoder->encode(value1);
    return plain1;
}

void Afseal::decode(Plaintext& plain1, int value1) {
    value1 = intEncoder->decode_int32(plain1);
}

int Afseal::noiseLevel(Ciphertext& cipher1) {
    int noiseLevel = decryptor->invariant_noise_budget(cipher1);
    return noiseLevel;
}

// ------------------------------- BOOTSTRAPPING ------------------------------
void Afseal::relinKeyGen(int bitCount){
  if(bitCount>dbc_max()){throw std::invalid_argument("bitCount must be =< 60");}
  if(bitCount<dbc_min()){throw std::invalid_argument("bitCount must be >= 1");}
  keyGenObj->generate_evaluation_keys(bitCount, *relinKey);
}
void Afseal::relinearize(Ciphertext cipher1){
  >evaluator->relinearize(cipher1, *relinKey);
}


// --------------------------------- OPERATIONS -------------------------------

void Afseal::negate(Ciphertext& cipher1){ evaluator->negate(cipher1);}
void Afseal::square(Ciphertext& cipher1){ this->evaluator->square(cipher1);}
void Afseal::add(Ciphertext& cipher1, Ciphertext& cipher2){
  evaluator->add(cipher1, cipher2);
}
void Afseal::multiply(Ciphertext& cipher1, Ciphertext& cipher2){
  evaluator->multiply(cipher1, cipher2);
}


// ------------------------------------- I/O ----------------------------------
// SAVE CONTEXT
bool Afseal::saveContext(string fileName){
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
bool Afseal::restoreContext(string fileName){
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
        this->nSlots = ea->size();                    // Refill nslots
        this->p = p1;
        this->r = r1;
    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}



// ----------------------------- AUXILIARY ----------------------------
// GETTERS
PublicKey getsecretKey()	 {return this->secretKey;}
SecretKey getpublicKey()	 {return this->publicKey;}
EvaluationKeys getevKey()	 {return this->evKeys;}
long Afseal::getnSlots()     {this->nSlots = ea->size(); return this->nSlots;}
long Afseal::getm()          {return this->m;}
long Afseal::getp()          {return this->p;}
long Afseal::getr()          {return this->r;}
long Afseal::getp2r() const  {return this->ea.getAlMod().getPPowR()}
bool Afseal::getflagVerbose(){return this->flagVerbose;}
bool Afseal::getflagTime()   {return this->flagTime;}
long Afseal::relinBitCount() {return this->evKeys.decomposition_bit_count()}
// SETTERS
void setpublicKey(PublicKey& pubKey)   	    {this->publicKey = pubKey;}
void setsecretKey(SecretKey& secKey)	    {this->secretKey = secKey}
void setsecretKey(EvaluationKeys& evKey)	{this->evKeys = evKey}
void Afseal::setflagVerbose(bool flagV) 	{this->flagVerbose = flagV;}
