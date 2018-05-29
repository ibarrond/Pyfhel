
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
}

Afseal::~Afseal(){}

// ------------------------------ CRYPTOGRAPHY --------------------------------
// GENERATION
void Afseal::ContextGen(long p, long m, long sec, bool f_Batch){

    EncryptionParameters parms;

    // m - cyclotomic polynomial exponent, must be power 2 in FV scheme
    bool m_is_pow2 = false;
    for (float i = 10; i < 30; i++) {
      if((float)(m)==pow(2, i)){m_is_pow2 = true;}}
    if(!m_is_pow2){throw invalid_argument("m must be power of 2 in SEAL");}

    // Context generation
    parms.set_poly_modulus("1x^"+to_string(m)+" + 1");
    if      (sec==128)  {parms.set_coeff_modulus(coeff_modulus_128(m));}
    else if (sec==192)  {parms.set_coeff_modulus(coeff_modulus_192(m));}
    else {throw invalid_argument("sec must be 128 or 192 bits.");}
    parms.set_plain_modulus(p);
    this->context = new SEALContext(parms);

    // Create Evaluator Key
    this->evaluator=new Evaluator(*context);
    if(f_Batch){
        if((*context).qualifiers().enable_batching){
            throw invalid_argument("p not prime | p-1 not multiple 2*m");
        }
        this->flagBatching=true;
        this->crtBuilder=new PolyCRTBuilder(*context);
    }
}

void Afseal::KeyGen(){
    this->keyGenObj = new KeyGenerator(*context);
    this->publicKey = new PublicKey(keyGenObj->public_key());   // Extract keys
    this->secretKey = new SecretKey(keyGenObj->secret_key());

    this->encryptor=new Encryptor(*context, *publicKey); // encr/decr objects
    this->decryptor=new Decryptor(*context, *secretKey);
}

// ENCRYPTION
Ciphertext Afseal::encrypt(Plaintext& plain1) {
    Ciphertext cipher1; encryptor->encrypt(plain1, cipher1);
    return cipher1;
    }
Ciphertext Afseal::encrypt(double& value1) {
    Ciphertext cipher1; encryptor->encrypt(fracEncoder->encode(value1), cipher1);
    return cipher1;
    }
Ciphertext Afseal::encrypt(int64_t& value1) {
    Ciphertext cipher1; encryptor->encrypt(intEncoder->encode(value1), cipher1);
    return cipher1;
    }
Ciphertext Afseal::encrypt(vector<int64_t>& value1) {
    Ciphertext cipher1; encryptor->encrypt(intEncoder->encode(value1), cipher1);
    return cipher1;
    }
void Afseal::encrypt(Plaintext& plain1, Ciphertext& cipher1) {
    encryptor->encrypt(plain1, cipher1);
    }
void Afseal::encrypt(double& value1, Ciphertext& cipher1) {
    encryptor->encrypt(fracEncoder->encode(value1), cipher1);
    }
void Afseal::encrypt(int64_t& value1, Ciphertext& cipher1) {
    encryptor->encrypt(intEncoder->encode(value1), cipher1);
    }

//DECRYPTION
Plaintext Afseal::decrypt(Ciphertext& cipher1) {
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    return plain1;
    }
void Afseal::decrypt(Ciphertext& cipher1, Plaintext& plain1) {
    decryptor->decrypt(cipher1, plain1);
    }
void Afseal::decrypt(Ciphertext& cipher1, int64_t& valueOut) {
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    valueOut = intEncoder->decode_int64(plain1);
    }
void Afseal::decrypt(Ciphertext& cipher1, double& valueOut) {
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    valueOut = fracEncoder->decode(plain1);
    }

// -------------------------------- ENCODING ----------------------------------

Plaintext Afseal::encode(int64_t& value1) {
    Plaintext plain1 = intEncoder->encode(value1);  return plain1;}
Plaintext Afseal::encode(double& value1) {
    Plaintext plain1 = fracEncoder->encode(value1); return plain1;}
Plaintext Afseal::encode(vector<int64_t> &values) { // Batching
    if(!flagBatching){throw invalid_argument("p not prime | 2*m*K ~= p-1 ");}
    Plaintext plain1; crtBuilder->compose(values, plain1); return plain1;}
vector<Plaintext> Afseal::encode(vector<int64_t> &values, bool dummy_notUsed){
    vector<Plaintext> plainVOut;
    for(int64_t& val:values){plainVOut.emplace_back(intEncoder->encode(val));}
    return plainVOut;}
vector<Plaintext> Afseal::encode(vector<double> &values) {
    vector<Plaintext> plainVOut;
    for(double& val:values){plainVOut.emplace_back(fracEncoder->encode(val));}
    return plainVOut;}


void Afseal::encode(int64_t& value1, Plaintext& plainOut){
    plainOut = intEncoder->encode(value1);}
void Afseal::encode(double& value1, Plaintext& plainOut){
    plainOut = fracEncoder->encode(value1);}
void Afseal::encode(vector<int64_t> &values, Plaintext& plainOut){
    if(values.size()>this->crtBuilder->slot_count()){
        throw range_error("Data vector size is bigger than nSlots");}
    crtBuilder->compose(values, plainOut);}
void Afseal::encode(vector<int64_t> &values, vector<Plaintext>& plainVOut){
    for(int64_t& val:values){plainVOut.emplace_back(intEncoder->encode(val));}}
void Afseal::encode(vector<double> &values, vector<Plaintext>& plainVOut){
    for(double& val:values){plainVOut.emplace_back(fracEncoder->encode(val));}}



void Afseal::decode(Plaintext& plain1, int64_t& valueOut) {
    valueOut = intEncoder->decode_int64(plain1);}
void Afseal::decode(Plaintext& plain1, double& valueOut) {
    valueOut = fracEncoder->decode(plain1);}
void Afseal::decode(Plaintext& plain1, vector<int64_t> &valueVOut) {
    valueVOut = fracEncoder->decode(plain1);}
void Afseal::decode(vector<Plaintext>& plainV, vector<int64_t> &valueVOut) {
    for(Plaintext& p:plainV){valueVOut.emplace_back(intEncoder->decode_int64(p));}}
void Afseal::decode(vector<Plaintext>& plain1, vector<double> &valueVOut) {
    value1 = fracEncoder->decode(plain1);}

int Afseal::noiseLevel(Ciphertext& cipher1) {
    int noiseLevel = decryptor->invariant_noise_budget(cipher1);
    return noiseLevel;
}

// ------------------------------- BOOTSTRAPPING ------------------------------
void Afseal::relinKeyGen(int& bitCount){
  if(bitCount>dbc_max()){throw invalid_argument("bitCount must be =< 60");}
  if(bitCount<dbc_min()){throw invalid_argument("bitCount must be >= 1");}
  relinKey = new EvaluationKeys();
  keyGenObj->generate_evaluation_keys(bitCount, *relinKey);
}
void Afseal::relinearize(Ciphertext& cipher1){
  evaluator->relinearize(cipher1, *relinKey);
}
void Afseal::galoisKeyGen(int& bitCount){
  if(bitCount>dbc_max()){throw invalid_argument("bitCount must be =< 60");}
  if(bitCount<dbc_min()){throw invalid_argument("bitCount must be >= 1");}
  GaloisKeys galKeys;
  keyGenObj->generate_evaluation_keys(bitCount, *relinKey);
}

// --------------------------------- OPERATIONS -------------------------------

void Afseal::negate(Ciphertext& cipher1){ evaluator->negate(cipher1);}
void Afseal::square(Ciphertext& cipher1){ evaluator->square(cipher1);}

void Afseal::add(vector<Ciphertext>& cipherV1, Ciphertext& cipherOut){
  evaluator->add_many(cipherV1, cipherOut);
}
void Afseal::add(Ciphertext& cipher1, Ciphertext& cipher2){
  evaluator->add(cipher1, cipher2);
}
void Afseal::add(Ciphertext& cipher1, Plaintext& plain2){
  evaluator->add_plain(cipher1, plain2);
}
void Afseal::multiply(Ciphertext& cipher1, Ciphertext& cipher2){
  evaluator->multiply(cipher1, cipher2);
}
void Afseal::multiply(Ciphertext& cipher1, Plaintext& plain1){
  evaluator->multiply_plain(cipher1, plain1);
}



// ------------------------------------- I/O ----------------------------------
// SAVE CONTEXT
bool Afseal::saveContext(string fileName){
    bool res=1;
    try{

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

    }
    catch(exception& e){
        res=0;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}



// --------------------------------- AUXILIARY --------------------------------
bool Afseal::batchEnabled(){return (*context).qualifiers().enable_batching;}
long Afseal::relinBitCount(){return this->relinKey->decomposition_bit_count();}

// GETTERS
SecretKey Afseal::getsecretKey()	 {return *(this->secretKey);}
PublicKey Afseal::getpublicKey()	 {return *(this->publicKey);}
EvaluationKeys Afseal::getrelinKey() {return *(this->relinKey);} 
int Afseal::getm()          {return this->m;}
int Afseal::getp()          {return this->p;}
int Afseal::getnSlots()     {return this->crtBuilder->slot_count();}
// SETTERS
void Afseal::setpublicKey(PublicKey& pubKey)   	 
    {this->publicKey = new PublicKey (pubKey);}
void Afseal::setsecretKey(SecretKey& secKey)	    
    {this->secretKey = new SecretKey (secKey);}
void Afseal::setrelinKey(EvaluationKeys& evKey)
    {this->relinKey = new EvaluationKeys(evKey);}