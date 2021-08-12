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
#include "Afseal.h"

using namespace std;
using namespace seal;



// =============================================================================
// ================================== AFSEAL ===================================
// =============================================================================

// ----------------------------- CLASS MANAGEMENT -----------------------------
Afseal::Afseal() {};

Afseal::Afseal(const Afseal &otherAfseal) {
  this->context = make_shared<SEALContext>(otherAfseal.context->first_context_data()->parms());

  //TODO: Copy Encoder ptr

  this->keyGenObj = make_shared<KeyGenerator>(*(this->context));
  this->secretKey = make_shared<SecretKey>(*(otherAfseal.secretKey));
  this->publicKey = make_shared<PublicKey>(*(otherAfseal.publicKey));
  this->relinKeys = make_shared<RelinKeys>(*(otherAfseal.relinKeys));
  this->rotateKeys = make_shared<GaloisKeys>(*(otherAfseal.rotateKeys));

  this->encryptor = make_shared<Encryptor>(*context, *publicKey, *secretKey);
  this->evaluator = make_shared<Evaluator>(*context);
  this->decryptor = make_shared<Decryptor>(*context, *secretKey);

  this->bfvEncoder = make_shared<BatchEncoder>(*context);
  this->ckksEncoder = make_shared<CKKSEncoder>(*context);

};

Afseal::~Afseal() {};

// -----------------------------------------------------------------------------
// ------------------------------ CRYPTOGRAPHY --------------------------------
// -----------------------------------------------------------------------------
// CONTEXT GENERATION
void Afseal::ContextGen(string scheme_t, uint64_t plain_modulus, size_t poly_modulus_degree, long sec, std::vector<int> qs) {

  if (scheme_t == "BFV"){

    EncryptionParameters parms(scheme_type::bfv);

    // Context generation
    parms.set_poly_modulus_degree(poly_modulus_degree);
    if      (sec==128) { parms.set_coeff_modulus(
      CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc128)); }
    else if (sec==192) { parms.set_coeff_modulus(
      CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc192)); }
    else if (sec==256) { parms.set_coeff_modulus(
      CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc256)); }
    else { throw invalid_argument("sec must be 128 or 192 or 256 bits."); }
    parms.set_plain_modulus(plain_modulus);
    this->context = make_shared<SEALContext>(parms);

    // Codec
    this->bfvEncoder = make_shared<BatchEncoder>(*context);

  }
  else if (scheme_t == "CKKS"){
    EncryptionParameters parms(scheme_type::ckks);

    // Context generation
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, qs));
    this->context = make_shared<SEALContext>(parms);

    // Codec
    this->ckksEncoder = make_shared<CKKSEncoder>(*context);
  }
  
  // Evaluator
  this->evaluator = make_shared<Evaluator>(*context);
  
  // Key generator
  this->keyGenObj = make_shared<KeyGenerator>(*context);
}

// KEY GENERATION
void Afseal::KeyGen() {
  if (context==NULL) { throw std::logic_error("Context not initialized"); }
  // Key generator
  this->keyGenObj = make_shared<KeyGenerator>(*context); // Refresh KeyGen obj

  this->publicKey = make_shared<PublicKey>();// Extract keys
  keyGenObj->create_public_key(*publicKey);
  this->secretKey = make_shared<SecretKey>(keyGenObj->secret_key());

  this->encryptor = make_shared<Encryptor>(*context, *publicKey);
  this->decryptor = make_shared<Decryptor>(*context, *secretKey);
}

void Afseal::relinKeyGen() {
  if (keyGenObj==NULL) { throw std::logic_error("Context not initialized"); }
  this->relinKeys = std::make_shared<RelinKeys>();
  keyGenObj->create_relin_keys(*relinKeys);
}

void Afseal::rotateKeyGen() {
  if (keyGenObj==NULL) { throw std::logic_error("Context not initialized"); }
  rotateKeys = make_shared<GaloisKeys>();
  keyGenObj->create_galois_keys(*rotateKeys);
}

// ENCRYPTION
void Afseal::encrypt(AfsealPtxt &plain1, AfsealCtxt &cipher1) {
  if (encryptor==NULL) { throw std::logic_error("Missing a Public Key"); }
  encryptor->encrypt(plain1, cipher1);
}

//DECRYPTION
void Afseal::decrypt(AfsealCtxt &cipher1, AfsealPtxt &plainOut) {
  if (decryptor==NULL) { throw std::logic_error("Missing a Private Key"); }
  decryptor->decrypt(cipher1, plainOut);
}

// NOISE MEASUREMENT
int Afseal::noise_level(AfsealCtxt &cipher1) {
  if (decryptor==NULL) { throw std::logic_error("Missing a Secret Key"); }
  return decryptor->invariant_noise_budget(cipher1);
}


// -----------------------------------------------------------------------------
// ---------------------------------- CODEC -----------------------------------
// -----------------------------------------------------------------------------
// ENCODE
// bfv
void Afseal::encode(vector<int64_t> &values, AfsealPtxt &plainOut) {
  if (bfvEncoder==NULL) { throw std::logic_error("Context not initialized with BATCH support"); }
  if (values.size() > this->bfvEncoder->slot_count()) {
    throw range_error("Data vector size is bigger than nSlots");
  }
  bfvEncoder->encode(values, plainOut);
}
// ckks
void Afseal::encode(vector<double> &values, double scale, AfsealPtxt &plainOut) {
  ckksEncoder->encode(values, scale, plainOut);
}
void Afseal::encode(std::vector<complex<double>> &values, double scale, AfsealPtxt &plainOut) {
  ckksEncoder->encode(values, scale, plainOut);
}

// DECODE
// bfv
void Afseal::decode(AfsealPtxt &plain1, std::vector<int64_t> &valueVOut) {
  if (bfvEncoder==NULL) { throw std::logic_error("Context not initialized with BATCH support"); }
  bfvEncoder->decode(plain1, valueVOut);
}
// ckks
void Afseal::decode(AfsealPtxt &plain1, vector<double> &valueVOut) {
  if (ckksEncoder==NULL) { throw std::logic_error("Context not initialized with BATCH support"); }
  ckksEncoder->decode(plain1, valueVOut);
}
void Afseal::decode(AfsealPtxt &plain1, vector<std::complex<double>> &valueVOut) {
  if (ckksEncoder==NULL) { throw std::logic_error("Context not initialized with BATCH support"); }
  ckksEncoder->decode(plain1, valueVOut);
}

// AUXILIARY
void Afseal::data(AfsealPtxt &ptxt, uint64_t *dest) {
  dest = ptxt.data();
}

// void Afseal::allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest) {
//   dest = &util::allocate_zero_poly(n, coeff_mod_count, pool)[0]; --> pool?
// }

// ------------------------------ RELINEARIZATION -----------------------------
void Afseal::relinearize(AfsealCtxt &cipher1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  if (relinKeys==NULL) { throw std::logic_error("Relinearization key not initialized"); }
  evaluator->relinearize_inplace(cipher1, *relinKeys);
}


// -----------------------------------------------------------------------------
// --------------------------------- OPERATIONS --------------------------------
// -----------------------------------------------------------------------------
// NEGATE
void Afseal::negate(AfsealCtxt &cipher1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->negate_inplace(cipher1);
}
void Afseal::negate(vector<AfsealCtxt> &cipherV) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  for (AfsealCtxt &c:cipherV) { evaluator->negate_inplace(c); }
}

// SQUARE
void Afseal::square(AfsealCtxt &cipher1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->square_inplace(cipher1);
}
void Afseal::square(vector<AfsealCtxt> &cipherV) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  for (AfsealCtxt &c:cipherV) { evaluator->square_inplace(c); }
}

// ADDITION
void Afseal::add(AfsealCtxt &cipherInOut, AfsealCtxt &cipher2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->add_inplace(cipherInOut, cipher2);
}
void Afseal::add(AfsealCtxt &cipherInOut, AfsealPtxt &plain2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->add_plain_inplace(cipherInOut, plain2);
}
void Afseal::add(vector<AfsealCtxt> &cipherVInOut, vector<AfsealCtxt> &cipherV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealCtxt>::iterator c2 = cipherV2.begin();
  for (; c1!=cipherVInOut.end(), c2!=cipherV2.end(); c1++, c2++) {
    evaluator->add_inplace(*c1, *c2);
  }
}
void Afseal::add(vector<AfsealCtxt> &cipherVInOut, vector<AfsealPtxt> &plainV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealPtxt>::iterator p2 = plainV2.begin();
  for (; c1!=cipherVInOut.end(), p2!=plainV2.end(); c1++, p2++) {
    evaluator->add_plain_inplace(*c1, *p2);
  }
}
void Afseal::cumsum(vector<seal::Ciphertext> &cipherV, AfsealCtxt &cipherOut) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->add_many(cipherV, cipherOut);
}

// SUBTRACTION
void Afseal::sub(AfsealCtxt &cipherInOut, AfsealCtxt &cipher2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->sub_inplace(cipherInOut, cipher2);
}
void Afseal::sub(AfsealCtxt &cipherInOut, AfsealPtxt &plain2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->sub_plain_inplace(cipherInOut, plain2);
}
void Afseal::sub(vector<AfsealCtxt> &cipherVInOut, vector<AfsealCtxt> &cipherV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealCtxt>::iterator c2 = cipherV2.begin();
  for (; c1!=cipherVInOut.end(), c2!=cipherV2.end(); c1++, c2++) {
    evaluator->sub_inplace(*c1, *c2);
  }
}
void Afseal::sub(vector<AfsealCtxt> &cipherVInOut, vector<AfsealPtxt> &plainV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealPtxt>::iterator p2 = plainV2.begin();
  for (; c1!=cipherVInOut.end(), p2!=plainV2.end(); c1++, p2++) {
    evaluator->sub_plain_inplace(*c1, *p2);
  }
}

// MULTIPLICATION
void Afseal::multiply(AfsealCtxt &cipherInOut, AfsealCtxt &cipher2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->multiply_inplace(cipherInOut, cipher2);
}
void Afseal::multiply(AfsealCtxt &cipherInOut, AfsealPtxt &plain1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->multiply_plain_inplace(cipherInOut, plain1);
}
void Afseal::multiply(vector<AfsealCtxt> &cipherVInOut, vector<AfsealCtxt> &cipherV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealCtxt>::iterator c2 = cipherV2.begin();
  for (; c1!=cipherVInOut.end(), c2!=cipherV2.end(); c1++, c2++) {
    evaluator->multiply_inplace(*c1, *c2);
  }
}
void Afseal::multiply(vector<AfsealCtxt> &cipherVInOut, vector<AfsealPtxt> &plainV2) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  vector<AfsealCtxt>::iterator c1 = cipherVInOut.begin();
  vector<AfsealPtxt>::iterator p2 = plainV2.begin();
  for (; c1!=cipherVInOut.end(), p2!=plainV2.end(); c1++, p2++) {
    evaluator->multiply_plain_inplace(*c1, *p2);
  }
}
void Afseal::cumprod(vector<seal::Ciphertext> &cipherV, AfsealCtxt &cipherOut) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  if (relinKeys==NULL) { throw std::logic_error("Relinearization key not initialized"); }
  evaluator->multiply_many(cipherV, *relinKeys, cipherOut);
}

// ROTATION
void Afseal::rotate(AfsealCtxt &cipher1, int &k) {
  if (rotateKeys==NULL) { throw std::logic_error("Rotation keys not initialized"); }
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->rotate_vector_inplace(cipher1, k, *rotateKeys);
}
void Afseal::rotate(vector<AfsealCtxt> &cipherV, int &k) {
  if (rotateKeys==NULL) { throw std::logic_error("Rotation keys not initialized"); }
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  for (AfsealCtxt &c:cipherV) { evaluator->rotate_vector_inplace(c, k, *rotateKeys); }
}

// POLYNOMIALS
void Afseal::exponentiate(AfsealCtxt &cipher1, uint64_t &expon) {
  if (relinKeys==NULL) { throw std::logic_error("Relinearization key not initialized"); }
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->exponentiate_inplace(cipher1, expon, *relinKeys);
}
void Afseal::exponentiate(vector<AfsealCtxt> &cipherV, uint64_t &expon) {
  if (relinKeys==NULL) { throw std::logic_error("Relinearization key not initialized"); }
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  for (AfsealCtxt &c:cipherV) { evaluator->exponentiate_inplace(c, expon, *relinKeys); }
}

// CKKS -> Rescaling and mod switching
void Afseal::rescale_to_next(AfsealCtxt &cipher1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->rescale_to_next_inplace(cipher1);
}

void Afseal::mod_switch_to_next(AfsealCtxt &cipher1) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->mod_switch_to_next_inplace(cipher1);
}

void Afseal::mod_switch_to_next(AfsealPtxt &ptxt) {
  if (evaluator==NULL) { throw std::logic_error("Context not initialized"); }
  evaluator->mod_switch_to_next_inplace(ptxt);
}



// -----------------------------------------------------------------------------
// ------------------------------------- I/O -----------------------------------
// -----------------------------------------------------------------------------
// SAVE/LOAD CONTEXT
size_t Afseal::save_context(ostream &out_stream, string &compr_mode) {
  if (context==NULL) { throw std::logic_error("Context not initialized"); }
  return (size_t)context->first_context_data()->parms().save(
    out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_context(istream &in_stream) {
  EncryptionParameters parms;
  size_t loaded_bytes = (size_t)parms.load(in_stream);
  this->context = make_shared<SEALContext>(parms);
  if (parms.scheme()==scheme_type::bfv) {
    this->bfvEncoder = make_shared<BatchEncoder>(*context);
  }
  else if (parms.scheme()==scheme_type::ckks) {
    this->ckksEncoder = make_shared<CKKSEncoder>(*context);
  }
  this->evaluator = make_shared<Evaluator>(*context);
  this->keyGenObj = make_shared<KeyGenerator>(*context);
  return loaded_bytes;
}

// SAVE/LOAD PUBLICKEY
size_t Afseal::save_public_key(ostream &out_stream, string &compr_mode) {
  if (publicKey==NULL) { throw std::logic_error("Public Key not initialized"); }
  return (size_t)publicKey->save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_public_key(istream &in_stream) {
  if (context==NULL) { throw std::logic_error("Context not initialized"); }
  this->publicKey = make_shared<PublicKey>();
  size_t loaded_bytes = (size_t)publicKey->load(*context, in_stream);
  this->encryptor = make_shared<Encryptor>(*context, *publicKey); 
  return loaded_bytes;
}

// SAVE/LOAD SECRETKEY
size_t Afseal::save_secret_key(ostream &out_stream, string &compr_mode) {
  if (secretKey==NULL) { throw std::logic_error("Secret Key not initialized"); }
  return (size_t)secretKey->save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_secret_key(istream &in_stream) {
  if (context==NULL) { throw std::logic_error("Context not initialized"); }
  this->secretKey = make_shared<SecretKey>();
  size_t loaded_bytes = (size_t)secretKey->load(*context, in_stream);
  this->decryptor = make_shared<Decryptor>(*context, *secretKey);
  return loaded_bytes;
}

// SAVE/LOAD RELINKEY
size_t Afseal::save_relin_keys(ostream &out_stream, string &compr_mode) {
  if (relinKeys==NULL) { throw std::logic_error("Relin Keys not initialized"); }
  return (size_t)relinKeys->save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_relin_keys(istream &in_stream) {
  if (keyGenObj==NULL) { throw std::logic_error("Context not initialized"); }
  this->relinKeys = make_shared<RelinKeys>();
  return (size_t)relinKeys->load(*context, in_stream);
}

// SAVE/LOAD ROTKEYS
size_t Afseal::save_rotate_keys(ostream &out_stream, string &compr_mode) {
  if (rotateKeys==NULL) { throw std::logic_error("Rotate Keys not initialized"); }
  return (size_t)rotateKeys->save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_rotate_keys(istream &in_stream) {
  if (keyGenObj==NULL) { throw std::logic_error("Context not initialized"); }
  this->rotateKeys = make_shared<GaloisKeys>();
  return (size_t)rotateKeys->load(*context, in_stream);
}

// SAVE/LOAD PLAINTEXT --> Could be achieved outside of Afseal
size_t Afseal::save_plaintext(ostream &out_stream, string &compr_mode, AfsealPtxt &plain) {
  return (size_t)plain.save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_plaintext(istream &in_stream, AfsealPtxt &plain) {
  return (size_t)plain.load(*context, in_stream);
}

// SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afseal
size_t Afseal::save_ciphertext(ostream &out_stream, string &compr_mode, AfsealCtxt &ciphert) {
  return (size_t)ciphert.save(out_stream, get_compr_mode(compr_mode));
}
size_t Afseal::load_ciphertext(istream &in_stream, AfsealCtxt &plain) {
  return (size_t)plain.load(*context, in_stream);
}


// -----------------------------------------------------------------------------
// -------------------------------- AUXILIARY ----------------------------------
// -----------------------------------------------------------------------------
bool Afseal::batchEnabled() {
  if (this->context==NULL) { throw std::logic_error("Context not initialized"); }
  return this->context->first_context_data()->qualifiers().using_batching;
}
long Afseal::maxBitCount(long poly_modulus_degree, int sec_level) {
  auto
      s = sec_level <= 128 ? sec_level_type::tc128 : (sec_level >= 256 ? sec_level_type::tc256 : sec_level_type::tc256);
  return CoeffModulus::MaxBitCount(poly_modulus_degree, s);
}
double Afseal::scale(AfsealCtxt &ctxt) {
  return ctxt.scale();
}
void Afseal::override_scale(AfsealCtxt &ctxt, double scale) {
  ctxt.scale() = scale;
}
// GETTERS
SecretKey Afseal::get_secretKey() {
  if (this->secretKey==NULL) { throw std::logic_error("Secret Key not initialized"); }
  return *(this->secretKey);
}
PublicKey Afseal::get_publicKey() {
  if (this->publicKey==NULL) { throw std::logic_error("Public Key not initialized"); }
  return *(this->publicKey);
}
RelinKeys Afseal::get_relinKeys() {
  if (this->relinKeys==NULL) { throw std::logic_error("Relinearization Keys not initialized"); }
  return *(this->relinKeys);
}
GaloisKeys Afseal::get_rotateKeys() {
  if (this->rotateKeys==NULL) { throw std::logic_error("Rotation Keys not initialized"); }
  return *(this->rotateKeys);
}
int Afseal::get_nSlots() {
  scheme_t scheme = this->get_scheme();
  if (scheme==scheme_t::bfv){
    if(this->bfvEncoder==NULL) {
    throw std::logic_error("Context not initialized with BFV scheme"); }
  return this->bfvEncoder->slot_count();
  }
  else if (scheme==scheme_t::ckks){
    if(this->ckksEncoder==NULL) {
    throw std::logic_error("Context not initialized with CKKS scheme"); }
  return this->ckksEncoder->slot_count();
  }
}
uint64_t Afseal::get_plain_modulus() {
  if (this->context==NULL) { throw std::logic_error("Context not initialized"); }
  return context->first_context_data()->parms().plain_modulus().value();
}
size_t Afseal::get_poly_modulus_degree() {
  if (this->context==NULL) { throw std::logic_error("Context not initialized"); }
  return context->first_context_data()->parms().poly_modulus_degree();
}

scheme_t Afseal::get_scheme() {
  if (this->context==NULL) { throw std::logic_error("Context not initialized"); }
  return scheme_map[context->first_context_data()->parms().scheme()];
}


// TODO: coeff_modulus?

// -----------------------------------------------------------------------------
// --------------------------------- POLYNOMS ----------------------------------
// -----------------------------------------------------------------------------
void Afseal::add_inplace(AfsealPoly &p1, AfsealPoly &p2) {
  p1.add_inplace(p2);
}

void Afseal::subtract_inplace(AfsealPoly &p1, AfsealPoly &p2) {
  p1.subtract_inplace(p2);
}

void Afseal::multiply_inplace(AfsealPoly &p1, AfsealPoly &p2) {
  p1.multiply_inplace(p2);
}

void Afseal::invert_inplace(AfsealPoly &poly) {
  if (!poly.invert_inplace()) {
    // TODO: How to communicate this information without throwing an exception?
    throw runtime_error("Inverse does not exist.");
  }
}

void Afseal::poly_to_ciphertext(AfsealPoly &p, AfsealCtxt &ctxt, size_t i) {
  // TODO: This shouldn't be too hard, just copy into position,
  //  but we need to ensure the sizes match,
  //  allocate a zero poly if the index doesn't exist, etc
  throw runtime_error("Not yet implemented.");
}

void Afseal::poly_to_plaintext(AfsealPoly &p, AfsealPtxt &ptxt) {
  // TODO: This shouldn't be too hard, just copy into position,
  //  but we need to ensure the sizes match,
  //  allocate a zero poly if the poly doesn't yet exist, etc
  throw runtime_error("Not yet implemented.");
}

std::complex<double> Afseal::get_coeff(AfsealPoly &poly, size_t i) {
  return poly.get_coeff(*this, i);
}

void Afseal::set_coeff(AfsealPoly &poly, complex<double> &val, size_t i) {
  poly.set_coeff(*this, val, i);
}

std::vector<std::complex<double>> Afseal::to_coeff_list(AfsealPoly &poly) {
  return poly.to_coeff_list(*this);
}






// =============================================================================
// ================================ AFSEALPOLY =================================
// =============================================================================

// ----------------------------- CLASS MANAGEMENT -----------------------------
AfsealPoly::AfsealPoly(AfsealPoly &other) {
  parms_id = other.parms_id;
  mempool = other.mempool;
  coeff_count = other.coeff_count;
  coeff_modulus = other.coeff_modulus;
  coeff_modulus_count = other.coeff_modulus_count;
  // copy the coefficients over
#pragma omp parallel for
  for (size_t i = 0; i < coeff_modulus_count; i++) {
    util::set_poly(other.eval_repr_coeff_iter + (i*coeff_count),
                   coeff_count,
                   1,
                   eval_repr_coeff_iter + (i*coeff_count));
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

AfsealPoly &AfsealPoly::operator=(AfsealPoly &other) {
  if (&other!=this) {
    parms_id = other.parms_id;
    mempool = other.mempool;
    coeff_count = other.coeff_count;
    coeff_modulus = other.coeff_modulus;
    coeff_modulus_count = other.coeff_modulus_count;

    // copy the coefficients over
#pragma omp parallel for
    for (size_t i = 0; i < coeff_modulus_count; i++) {
      util::set_poly(other.eval_repr_coeff_iter + (i*coeff_count),
                     coeff_count,
                     1,
                     eval_repr_coeff_iter + (i*coeff_count));
    }
    // invalidate the coeff_repr
    coeff_repr_valid = false;
  }
  return *this;
}

AfsealPoly::AfsealPoly(Afseal &afseal, const AfsealCtxt &ref) {
  parms_id = ref.parms_id();
  mempool = seal::MemoryManager::GetPool();
  coeff_count = ref.poly_modulus_degree();
  coeff_modulus = afseal.context->get_context_data(parms_id)->parms().coeff_modulus();
  coeff_modulus_count = afseal.context->get_context_data(parms_id)->parms().coeff_modulus().size();
  eval_repr_coeff_iter = util::allocate_zero_poly(coeff_count, coeff_modulus_count, mempool);
}

AfsealPoly::AfsealPoly(Afseal &afseal, AfsealCtxt &ctxt, size_t index) : AfsealPoly(afseal, ctxt) {
  // Copy coefficients from ctxt
#pragma omp parallel for
  for (size_t i = 0; i < coeff_modulus_count; i++) {
    util::set_poly(ctxt.data(index) + (i*coeff_count), coeff_count, 1, eval_repr_coeff_iter + (i*coeff_count));
  }
}

AfsealPoly::AfsealPoly(Afseal &afseal, AfsealPtxt &ptxt, const AfsealCtxt &ref) : AfsealPoly(afseal, ref) {
// Copy coefficients from ptxt
#pragma omp parallel for
  for (size_t i = 0; i < coeff_modulus_count; i++) {
    util::set_poly(ptxt.data() + (i*coeff_count), coeff_count, 1, eval_repr_coeff_iter + (i*coeff_count));
  }
}

// -------------------------------- COEFFICIENTS -------------------------------
void AfsealPoly::generate_coeff_repr(Afseal &afseal) {
  if (!coeff_repr_valid) {

    // Copy the coefficients over
#pragma omp parallel for
    for (size_t i = 0; i < coeff_modulus_count; i++) {
      util::set_poly(eval_repr_coeff_iter + (i*coeff_count), coeff_count, 1, coeff_repr_coeff_iter + (i*coeff_count));
    }

    // Now do the actual conversion
    auto small_ntt_tables = afseal.context->get_context_data(parms_id)->small_ntt_tables();
#pragma omp parallel for
    for (size_t j = 0; j < coeff_modulus_count; j++) {
      util::inverse_ntt_negacyclic_harvey(coeff_repr_coeff_iter + (j*coeff_count), small_ntt_tables[j]); // non-ntt form
    }

    // set valid flag
    coeff_repr_valid = true;
  }
}

std::vector<std::complex<double>> AfsealPoly::to_coeff_list(Afseal &afseal) {
  generate_coeff_repr(afseal);
  //TODO: Need to also decompose the CRT representation
  // and then do some more magic!
  throw runtime_error("Not yet implemented.");
}

std::complex<double> AfsealPoly::get_coeff(Afseal &afseal, size_t i) {
  return to_coeff_list(afseal)[i];
}

void AfsealPoly::set_coeff(Afseal &afseal, std::complex<double> &val, size_t i) {
  auto v = to_coeff_list(afseal);
  v[i] = val;
  // TODO: Convert vector back into CRT, then apply NTT
  //  don't forget to also write the coeff_repr and set the valid bit,
  //  since we already have the data around!
  throw runtime_error("Not yet implemented.");
}

// -------------------------------- OPERATIONS ---------------------------------
void AfsealPoly::add_inplace(const AfsealPoly &other) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::add_poly_coeffmod(eval_repr_coeff_iter + (j*coeff_count),
                            other.eval_repr_coeff_iter + (j*coeff_count),
                            coeff_count,
                            coeff_modulus[j],
                            eval_repr_coeff_iter      //TODO: Check if this is safe (used to be result + ..)
                                + (j*coeff_count));
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

void AfsealPoly::subtract_inplace(const AfsealPoly &other) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::sub_poly_coeffmod(eval_repr_coeff_iter + (j*coeff_count),
                            other.eval_repr_coeff_iter + (j*coeff_count),
                            coeff_count,
                            coeff_modulus[j],
                            eval_repr_coeff_iter  //TODO: Check if this is safe (used to be result + ..)
                                + (j*coeff_count));
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

void AfsealPoly::multiply_inplace(const AfsealPoly &other) {
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    util::dyadic_product_coeffmod(eval_repr_coeff_iter + (j*coeff_count),
                                  other.eval_repr_coeff_iter + (j*coeff_count),
                                  coeff_count,
                                  coeff_modulus[j],
                                  eval_repr_coeff_iter  //TODO: Check if this is safe (used to be result + ..)
                                      + (j*coeff_count));
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

bool AfsealPoly::invert_inplace() {
  // compute a^{-1}, where a is a double-CRT polynomial whose evaluation representation
  // is in a. The double-CRT representation in SEAL is stored as a flat array of
  // length coeff_count * modulus_count:
  //    [ 0 .. coeff_count-1 , coeff_count .. 2*coeff_count-1, ... ]
  //      ^--- a (mod p0)    , ^--- a (mod p1),              ,  ...
  // return if the inverse exists, and result is also in evaluation representation

  bool *has_inv = new bool[coeff_modulus_count];
  fill_n(has_inv, coeff_modulus_count, true);
#pragma omp parallel for
  for (size_t j = 0; j < coeff_modulus_count; j++) {
    for (size_t i = 0; i < coeff_count && has_inv[j]; i++) {
      uint64_t inv = 0;
      if (util::try_invert_uint_mod(eval_repr_coeff_iter[i + (j*coeff_count)], coeff_modulus[j], inv)) {
        eval_repr_coeff_iter[i + (j*coeff_count)] = inv; //TODO: Check if this is safe (used to be result[...])
      } else {
        has_inv[j] = false;
      }
    }
  }
  for (size_t j = 0; j < coeff_modulus.size(); j++) {
    // invalidate the coeff_repr
    coeff_repr_valid = false;
    if (!has_inv[j]) return false;
  }
  delete[] has_inv;

  // invalidate the coeff_repr
  coeff_repr_valid = false;

  return true;
}
