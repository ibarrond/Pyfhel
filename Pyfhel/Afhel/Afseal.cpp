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
#include <assert.h>     /* assert */

#include "Afseal.h"

// ----------------------------- CLASS MANAGEMENT -----------------------------
Afseal::Afseal(){}

Afseal::Afseal(const Afseal &otherAfseal){
    this->context = make_shared<SEALContext>(*(otherAfseal.context));

    this->intEncoder =   make_shared<IntegerEncoder>(*(otherAfseal.intEncoder));
    this->fracEncoder =  make_shared<FractionalEncoder>(*(otherAfseal.fracEncoder));

    this->keyGenObj =    make_shared<KeyGenerator>(*(this->context));
    this->secretKey =    make_shared<SecretKey>(*(otherAfseal.secretKey));
    this->publicKey =    make_shared<PublicKey>(*(otherAfseal.publicKey));
    this->relinKey =     make_shared<EvaluationKeys>(*(otherAfseal.relinKey));
    this->rotateKeys =      make_shared<GaloisKeys>(*(otherAfseal.rotateKeys));
    
    this->encryptor =    make_shared<Encryptor>(*(otherAfseal.encryptor));
    this->evaluator =    make_shared<Evaluator>(*(otherAfseal.evaluator));
    this->decryptor =    make_shared<Decryptor>(*(otherAfseal.decryptor));
    
    this->crtBuilder =   make_shared<PolyCRTBuilder>(*(otherAfseal.crtBuilder));

    this->m =            otherAfseal.m;
    this->p =            otherAfseal.p;
    this->base =         otherAfseal.base;
    this->sec =          otherAfseal.sec;
    this->intDigits =    otherAfseal.intDigits;
    this->fracDigits =   otherAfseal.fracDigits;
    this->flagBatch    = otherAfseal.flagBatch;
}

Afseal::~Afseal(){}

// ------------------------------ CRYPTOGRAPHY --------------------------------
// CONTEXT GENERATION
void Afseal::ContextGen(long new_p, long new_m, bool new_flagBatch, 
                        long new_base, long new_sec, int new_intDigits, 
                        int new_fracDigits){
	
    EncryptionParameters parms;
	this->p = new_p;    	this->m = new_m;
	this->base = new_base;	this->sec = new_sec;
	this->intDigits = new_intDigits; 
	this->fracDigits = new_fracDigits;
	this->flagBatch = new_flagBatch;

    // Context generation
    parms.set_poly_modulus("1x^"+to_string(m)+" + 1");
    if      (sec==128)  {parms.set_coeff_modulus(coeff_modulus_128(m));}
    else if (sec==192)  {parms.set_coeff_modulus(coeff_modulus_192(m));}
    else if (sec==256)  {parms.set_coeff_modulus(coeff_modulus_256(m));}
    else {throw invalid_argument("sec must be 128 or 192 or 256 bits.");}
    parms.set_plain_modulus(p);
    this->context = shared_ptr<SEALContext>(new SEALContext(parms));

    // Codec
    this->intEncoder = make_shared<IntegerEncoder>((*context).plain_modulus(), base);
    this->fracEncoder = make_shared<FractionalEncoder>((*context).plain_modulus(),
              (*context).poly_modulus(), intDigits, fracDigits, base);

    // Create Evaluator Key
    this->evaluator=make_shared<Evaluator>(*context);
    if(this->flagBatch){
        if(!(*context).qualifiers().enable_batching){
            throw invalid_argument("p not prime or p-1 not multiple 2*m");
        }
        this->crtBuilder=make_shared<PolyCRTBuilder>(*context);
    }
}
 

// KEY GENERATION
void Afseal::KeyGen(){
    if(context==NULL){throw std::logic_error("Context not initialized");}

    this->keyGenObj = make_shared<KeyGenerator>(*context);
    this->publicKey = make_shared<PublicKey>(keyGenObj->public_key());   // Extract keys
    this->secretKey = make_shared<SecretKey>(keyGenObj->secret_key());

    this->encryptor= make_shared<Encryptor>(*context, *publicKey); // encr/decr objects
    this->decryptor= make_shared<Decryptor>(*context, *secretKey);
}


// ENCRYPTION
Ciphertext Afseal::encrypt(Plaintext& plain1) {
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    Ciphertext cipher1; encryptor->encrypt(plain1, cipher1);
    return cipher1;}
Ciphertext Afseal::encrypt(double& value1) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    Ciphertext cipher1; encryptor->encrypt(fracEncoder->encode(value1),cipher1);
    return cipher1;}
Ciphertext Afseal::encrypt(int64_t& value1) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    Ciphertext cipher1; encryptor->encrypt(intEncoder->encode(value1),cipher1);
    return cipher1;}
Ciphertext Afseal::encrypt(vector<int64_t>& valueV) {
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    Ciphertext cipher1; Plaintext plain1;
    crtBuilder->compose(valueV, plain1);
    encryptor->encrypt(plain1, cipher1); 
    return cipher1;}
vector<Ciphertext> Afseal::encrypt(vector<int64_t>& valueV, bool& dummy_NoBatch){
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    vector<Ciphertext> cipherV; Ciphertext cipher1;
    for(int64_t& v:valueV){
        encryptor->encrypt(intEncoder->encode(v), cipher1);
        cipherV.emplace_back(cipher1);}
    return cipherV;}
vector<Ciphertext> Afseal::encrypt(vector<double>& valueV) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    vector<Ciphertext> cipherV; Ciphertext cipher1;
    for(double& v:valueV){
        encryptor->encrypt(fracEncoder->encode(v), cipher1);
        cipherV.emplace_back(cipher1);}
    return cipherV;}

void Afseal::encrypt(Plaintext& plain1, Ciphertext& cipher1) {
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    encryptor->encrypt(plain1, cipher1);}
void Afseal::encrypt(double& value1, Ciphertext& cipher1) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    encryptor->encrypt(fracEncoder->encode(value1), cipher1);}
void Afseal::encrypt(int64_t& value1, Ciphertext& cipher1) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    encryptor->encrypt(intEncoder->encode(value1), cipher1);}
void Afseal::encrypt(vector<int64_t>& valueV, Ciphertext& cipherOut){
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    Plaintext plain1; crtBuilder->compose(valueV, plain1);
    encryptor->encrypt(plain1, cipherOut);}
void Afseal::encrypt(vector<int64_t>& valueV, vector<Ciphertext>& cipherOut){
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    Ciphertext cipher1;
    for(int64_t& v:valueV){
        encryptor->encrypt(intEncoder->encode(v), cipher1);
        cipherOut.emplace_back(cipher1);}}
void Afseal::encrypt(vector<double>& valueV, vector<Ciphertext>& cipherOut){
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(encryptor==NULL){throw std::logic_error("Missing a Public Key");}
    Ciphertext cipher1;
    for(double& v:valueV){
        encryptor->encrypt(fracEncoder->encode(v), cipher1);
        cipherOut.emplace_back(cipher1);}}


//DECRYPTION
vector<int64_t> Afseal::decrypt(Ciphertext& cipher1) {
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    Plaintext plain1;
    vector<int64_t> valueVOut;
    decryptor->decrypt(cipher1, plain1);
    crtBuilder->decompose(plain1, valueVOut);
	return valueVOut;
    }
void Afseal::decrypt(Ciphertext& cipher1, Plaintext& plain1) {
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    decryptor->decrypt(cipher1, plain1);}
void Afseal::decrypt(Ciphertext& cipher1, int64_t& valueOut) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    valueOut = intEncoder->decode_int64(plain1);}
void Afseal::decrypt(Ciphertext& cipher1, double& valueOut) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    Plaintext plain1; decryptor->decrypt(cipher1, plain1);
    valueOut = fracEncoder->decode(plain1);}
void Afseal::decrypt(vector<Ciphertext>& cipherV, vector<int64_t>& valueVOut) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    Plaintext plain1;
    for(Ciphertext& c:cipherV){
        decryptor->decrypt(c, plain1);
        valueVOut.emplace_back(intEncoder->decode_int64(plain1));}}
void Afseal::decrypt(vector<Ciphertext>& cipherV, vector<double>& valueVOut) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    Plaintext plain1;
    for(Ciphertext& c:cipherV){
        decryptor->decrypt(c, plain1);
        valueVOut.emplace_back(fracEncoder->decode(plain1));}}
void Afseal::decrypt(Ciphertext& cipher1, vector<int64_t>& valueVOut){
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    Plaintext plain1;
    decryptor->decrypt(cipher1, plain1);
    crtBuilder->decompose(plain1, valueVOut);
}

// ---------------------------------- CODEC -----------------------------------
// ENCODE
Plaintext Afseal::encode(int64_t& value1) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    return intEncoder->encode(value1); }
Plaintext Afseal::encode(double& value1) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    return fracEncoder->encode(value1); }
Plaintext Afseal::encode(vector<int64_t> &values) { // Batching
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    Plaintext plain1; crtBuilder->compose(values, plain1); return plain1;}
vector<Plaintext> Afseal::encode(vector<int64_t> &values, bool dummy_notUsed){
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    vector<Plaintext> plainVOut;
    for(int64_t& val:values){plainVOut.emplace_back(intEncoder->encode(val));}
    return plainVOut;}
vector<Plaintext> Afseal::encode(vector<double> &values) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    vector<Plaintext> plainVOut;
    for(double& val:values){plainVOut.emplace_back(fracEncoder->encode(val));}
    return plainVOut;}


void Afseal::encode(int64_t& value1, Plaintext& plainOut){
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    plainOut = intEncoder->encode(value1);}
void Afseal::encode(double& value1, Plaintext& plainOut){
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    plainOut = fracEncoder->encode(value1);}
void Afseal::encode(vector<int64_t> &values, Plaintext& plainOut){
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    if(values.size()>this->crtBuilder->slot_count()){
        throw range_error("Data vector size is bigger than nSlots");}
    crtBuilder->compose(values, plainOut);}
void Afseal::encode(vector<int64_t> &values, vector<Plaintext>& plainVOut){
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    for(int64_t& val:values){
        plainVOut.emplace_back(intEncoder->encode(val));}}
void Afseal::encode(vector<double> &values, vector<Plaintext>& plainVOut){
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    for(double& val:values){
        plainVOut.emplace_back(fracEncoder->encode(val));}}

// DECODE
vector<int64_t> Afseal::decode(Plaintext& plain1) {
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    vector<int64_t> valueVOut;
    crtBuilder->decompose(plain1, valueVOut);
	return valueVOut;
    }
void Afseal::decode(Plaintext& plain1, int64_t& valueOut) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    valueOut = intEncoder->decode_int64(plain1);}
void Afseal::decode(Plaintext& plain1, double& valueOut) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    valueOut = fracEncoder->decode(plain1);}
void Afseal::decode(Plaintext& plain1, vector<int64_t> &valueVOut) {
    if(crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
    crtBuilder->decompose(plain1, valueVOut);}
void Afseal::decode(vector<Plaintext>& plainV, vector<int64_t> &valueVOut) {
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    for(Plaintext& pl:plainV){
        valueVOut.emplace_back(intEncoder->decode_int64(pl));}}
void Afseal::decode(vector<Plaintext>& plainV, vector<double> &valueVOut) {
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    for(Plaintext& pl:plainV){
        valueVOut.emplace_back(fracEncoder->decode(pl));}}

// NOISE MEASUREMENT
int Afseal::noiseLevel(Ciphertext& cipher1) {
    if(decryptor==NULL){throw std::logic_error("Missing a Private Key");}
    return decryptor->invariant_noise_budget(cipher1);}

// ------------------------------ RELINEARIZATION -----------------------------
void Afseal::relinKeyGen(int& bitCount, int& size){
    if(keyGenObj==NULL){throw std::logic_error("Context not initialized");}
    if(bitCount>dbc_max()){throw invalid_argument("bitCount must be =< 60");}
    if(bitCount<dbc_min()){throw invalid_argument("bitCount must be >= 1");}
    this->relinKey = make_shared<EvaluationKeys>();
    this->keyGenObj->generate_evaluation_keys(bitCount, size, *relinKey);
}
void Afseal::relinearize(Ciphertext& cipher1){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    if(relinKey==NULL){throw std::logic_error("Relinearization key not initialized");}
    evaluator->relinearize(cipher1, *relinKey);
}
void Afseal::rotateKeyGen(int& bitCount){
    if(keyGenObj==NULL){throw std::logic_error("Context not initialized");}
    if(bitCount>dbc_max()){throw invalid_argument("bitCount must be =< 60");}
    if(bitCount<dbc_min()){throw invalid_argument("bitCount must be >= 1");}
    rotateKeys = make_shared<GaloisKeys>();
    keyGenObj->generate_galois_keys(bitCount, *rotateKeys);
}

// --------------------------------- OPERATIONS -------------------------------
// NOT
void Afseal::negate(Ciphertext& cipher1){ 
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->negate(cipher1);}
void Afseal::negate(vector<Ciphertext>& cipherV){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    for (Ciphertext& c:cipherV){evaluator->negate(c);}}
// SQUARE
void Afseal::square(Ciphertext& cipher1){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
     evaluator->square(cipher1);}
void Afseal::square(vector<Ciphertext>& cipherV){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    for (Ciphertext& c:cipherV){evaluator->square(c);}}

// ADDITION
void Afseal::add(Ciphertext& cipherInOut, Ciphertext& cipher2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->add(cipherInOut, cipher2);}
void Afseal::add(Ciphertext& cipherInOut, Plaintext& plain2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->add_plain(cipherInOut, plain2);}
void Afseal::add(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Ciphertext>::iterator c2 = cipherV2.begin();
    for(; c1 != cipherVInOut.end(), c2 != cipherV2.end(); c1++, c2++){
            evaluator->add(*c1, *c2);}}
void Afseal::add(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Plaintext>::iterator p2 = plainV2.begin();
    for(; c1 != cipherVInOut.end(), p2 != plainV2.end(); c1++, p2++){
        evaluator->add_plain(*c1, *p2);}}
void Afseal::add(vector<Ciphertext>& cipherV, Ciphertext& cipherOut){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->add_many(cipherV, cipherOut);}

// SUBSTRACTION
void Afseal::sub(Ciphertext& cipherInOut, Ciphertext& cipher2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->sub(cipherInOut, cipher2);}
void Afseal::sub(Ciphertext& cipherInOut, Plaintext& plain2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->sub_plain(cipherInOut, plain2);}
void Afseal::sub(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Ciphertext>::iterator c2 = cipherV2.begin();
    for(; c1 != cipherVInOut.end(), c2 != cipherV2.end(); c1++, c2++){
        evaluator->sub(*c1, *c2);}}
void Afseal::sub(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Plaintext>::iterator p2 = plainV2.begin();
    for(; c1 != cipherVInOut.end(), p2 != plainV2.end(); c1++, p2++){
        evaluator->sub_plain(*c1, *p2);}}

// MULTIPLICATION
void Afseal::multiply(Ciphertext& cipherInOut, Ciphertext& cipher2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->multiply(cipherInOut, cipher2);}
void Afseal::multiply(Ciphertext& cipherInOut, Plaintext& plain1){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->multiply_plain(cipherInOut, plain1);}
void Afseal::multiply(vector<Ciphertext>& cipherVInOut, vector<Ciphertext>& cipherV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Ciphertext>::iterator c2 = cipherV2.begin();
    for(; c1 != cipherVInOut.end(), c2 != cipherV2.end(); c1++, c2++){
            evaluator->multiply(*c1, *c2);}}
void Afseal::multiply(vector<Ciphertext>& cipherVInOut, vector<Plaintext>& plainV2){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    vector<Ciphertext>::iterator c1 = cipherVInOut.begin();
    vector<Plaintext>::iterator p2 = plainV2.begin();
    for(; c1 != cipherVInOut.end(), p2 != plainV2.end(); c1++, p2++){
        evaluator->multiply_plain(*c1, *p2);}}
void Afseal::multiply(vector<Ciphertext>& cipherV, Ciphertext& cipherOut){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    if(relinKey==NULL){throw std::logic_error("Relinearization key not initialized");}
    evaluator->multiply_many(cipherV, *relinKey, cipherOut);}


// ROTATION
void Afseal::rotate(Ciphertext& cipher1, int& k){
    if(rotateKeys==NULL){throw std::logic_error("Rotation keys not initialized");}
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->rotate_rows(cipher1, k, *rotateKeys);}
void Afseal::rotate(vector<Ciphertext>& cipherV, int& k){
    if(rotateKeys==NULL){throw std::logic_error("Rotation keys not initialized");}
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    for (Ciphertext& c:cipherV){evaluator->rotate_rows(c, k, *rotateKeys);}}


// POLYNOMIALS
void Afseal::exponentiate(Ciphertext& cipher1, uint64_t& expon){
	if(relinKey==NULL){throw std::logic_error("Relinearization key not initialized");}
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    evaluator->exponentiate(cipher1, expon, *relinKey);}
void Afseal::exponentiate(vector<Ciphertext>& cipherV, uint64_t& expon){
    if(relinKey==NULL){throw std::logic_error("Relinearization key not initialized");}
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    for (Ciphertext& c:cipherV){evaluator->exponentiate(c, expon, *relinKey);}}

void Afseal::polyEval(Ciphertext& cipher1, vector<int64_t>& coeffPoly){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    if(intEncoder==NULL){throw std::logic_error("Context not initialized");}
    Ciphertext res;
    evaluator->multiply_plain(cipher1, intEncoder->encode(coeffPoly[0]), res);
    evaluator->add_plain(cipher1, intEncoder->encode(coeffPoly[1]));
    coeffPoly.erase(coeffPoly.begin(), coeffPoly.begin()+1);
    for (int64_t coeff: coeffPoly){
        evaluator->multiply(res, cipher1);
        evaluator->add_plain(cipher1, intEncoder->encode(coeff));}}

void Afseal::polyEval(Ciphertext& cipher1, vector<double>& coeffPoly){
    if(evaluator==NULL){throw std::logic_error("Context not initialized");}
    if(fracEncoder==NULL){throw std::logic_error("Context not initialized");}
    Ciphertext res;
    evaluator->multiply_plain(cipher1, fracEncoder->encode(coeffPoly[0]), res);
    evaluator->add_plain(cipher1, fracEncoder->encode(coeffPoly[1]));
    coeffPoly.erase(coeffPoly.begin(), coeffPoly.begin()+1);
    for (double coeff: coeffPoly){
        evaluator->multiply(res, cipher1);
        evaluator->add_plain(cipher1, fracEncoder->encode(coeff));}}

// ------------------------------------- I/O ----------------------------------
// SAVE/RESTORE CONTEXT
bool Afseal::saveContext(string fileName){
    if(context==NULL){throw std::logic_error("Context not initialized");}
    bool res=true;
    try{
        fstream contextFile(fileName, fstream::out|fstream::trunc|fstream::binary);
        assert(contextFile.is_open());
        context->parms().save(contextFile);
        contextFile << base << endl;
        contextFile << sec << endl;
        contextFile << intDigits << endl;
        contextFile << fracDigits << endl;
        contextFile << flagBatch << endl;
        
        contextFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: context could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::restoreContext(string fileName){
    EncryptionParameters parms;
    bool res=true;
    try{    
        fstream contextFile(fileName, fstream::in|fstream::binary);
        assert(contextFile.is_open());
        parms.load(contextFile);
        contextFile >> base;
        contextFile >> sec;
        contextFile >> intDigits;
        contextFile >> fracDigits;
        contextFile >> flagBatch;
        contextFile.close();

        this->context = make_shared<SEALContext>(parms);
		this->keyGenObj = make_shared<KeyGenerator>(*context);
        this->intEncoder = make_shared<IntegerEncoder>((*context).plain_modulus(), base);
        this->fracEncoder = make_shared<FractionalEncoder>((*context).plain_modulus(),
                (*context).poly_modulus(), intDigits, fracDigits, base);
        this->evaluator=make_shared<Evaluator>(*context);
        if(flagBatch){
            if(!(*context).qualifiers().enable_batching){
                throw invalid_argument("p not prime | p-1 not multiple 2*m");
            }
            this->flagBatch=true;
            this->crtBuilder=make_shared<PolyCRTBuilder>(*context);
        }
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: context could not be loaded";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

// SAVE/RESTORE KEYS
bool Afseal::savepublicKey(string fileName){
    if(publicKey==NULL){throw std::logic_error("Public Key not initialized");}
    bool res=true;
    try{fstream keyFile(fileName, fstream::out|fstream::trunc|fstream::binary);
        assert(keyFile.is_open());
        publicKey->save(keyFile);
        
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: public key could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::restorepublicKey(string fileName){
    bool res=true;
    try{        
        fstream keyFile(fileName, fstream::in|fstream::binary);
        assert(keyFile.is_open());
        this->publicKey = make_shared<PublicKey>();
        this->publicKey->load(keyFile);
        this->encryptor=make_shared<Encryptor>(*context, *publicKey);
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: public key could not be loaded";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::savesecretKey(string fileName){
    if(publicKey==NULL){throw std::logic_error("Secret Key not initialized");}
    bool res=true;
    try{fstream keyFile(fileName, fstream::out|fstream::trunc|fstream::binary);
        assert(keyFile.is_open());
        secretKey->save(keyFile);
        
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: secret key could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::restoresecretKey(string fileName){
    bool res=true;
    try{        
        fstream keyFile(fileName, fstream::in|fstream::binary);
        assert(keyFile.is_open());
        this->secretKey = make_shared<SecretKey>();
        this->secretKey->load(keyFile);
        this->decryptor=make_shared<Decryptor>(*context, *secretKey);
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: secret key could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::saverelinKey(string fileName){
    if(relinKey==NULL){throw std::logic_error("Relinearization Key not initialized");}
    bool res=true;
    try{fstream keyFile(fileName, fstream::out|fstream::trunc|fstream::binary);
        assert(keyFile.is_open());
        relinKey->save(keyFile);
        
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: relinearization key could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::restorerelinKey(string fileName){
    bool res=true;
    try{        
        fstream keyFile(fileName, fstream::in|fstream::binary);
        assert(keyFile.is_open());
        this->relinKey = make_shared<EvaluationKeys>();
        this->relinKey->load(keyFile);
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: relinearization key could not be loaded";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::saverotateKey(string fileName){
    if(rotateKeys==NULL){throw std::logic_error("Rotation Key not initialized");}
    bool res=true;
    try{fstream keyFile(fileName, fstream::out|fstream::trunc|fstream::binary);
        assert(keyFile.is_open());
        rotateKeys->save(keyFile);
        
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: Galois could not be saved";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}

bool Afseal::restorerotateKey(string fileName){
    bool res=true;
    try{        
        fstream keyFile(fileName, fstream::in|fstream::binary);
        assert(keyFile.is_open());
        this->rotateKeys = make_shared<GaloisKeys>();
        this->rotateKeys->load(keyFile);
        keyFile.close();
    }
    catch(exception& e){
        std::cout << "Afseal ERROR: Galois could not be loaded";
        res=false;
    }
    return res;                                 // 1 if all OK, 0 otherwise
}


// ----------------------------- AUXILIARY ----------------------------
bool Afseal::batchEnabled() { 
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->context->qualifiers().enable_batching;}
long Afseal::relinBitCount(){
	if(this->relinKey==NULL){throw std::logic_error("Relinearization Key not initialized");}
	return this->relinKey->decomposition_bit_count();}

// GETTERS
SecretKey Afseal::getsecretKey()    {
	if(this->secretKey==NULL){throw std::logic_error("Secret Key not initialized");}
	return *(this->secretKey);}
PublicKey Afseal::getpublicKey()    {
	if(this->publicKey==NULL){throw std::logic_error("Public Key not initialized");}
	return *(this->publicKey);}
EvaluationKeys Afseal::getrelinKey(){
	if(this->relinKey==NULL){throw std::logic_error("Relinearization Key not initialized");}
	return *(this->relinKey);} 
GaloisKeys Afseal::getrotateKeys()  {
	if(this->rotateKeys==NULL){throw std::logic_error("Rotation Key not initialized");}
	return *(this->rotateKeys);} 
int Afseal::getnSlots()        {
	if(this->crtBuilder==NULL){throw std::logic_error("Context not initialized with BATCH support");}
	return this->crtBuilder->slot_count();}   
int Afseal::getp()             {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->p;}
int Afseal::getm()             {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->m;}
int Afseal::getbase()          {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->base;}
int Afseal::getsec()           {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->sec;}
int Afseal::getintDigits()     {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->intDigits;}
int Afseal::getfracDigits()    {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->fracDigits;}
bool Afseal::getflagBatch()    {
	if(this->context==NULL){throw std::logic_error("Context not initialized");}
	return this->flagBatch;}
