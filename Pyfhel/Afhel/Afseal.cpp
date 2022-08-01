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

#include <chrono>
#include <thread>
#include <cmath>

// =============================================================================
// ================================== AFSEAL ===================================
// =============================================================================

// ----------------------------- CLASS MANAGEMENT -----------------------------
Afseal::Afseal(){};

Afseal::Afseal(const Afseal &otherAfseal)
{
  this->context = make_shared<SEALContext>(otherAfseal.context->first_context_data()->parms());

  // TODO: Copy Encoder ptr

  this->keyGenObj = make_shared<KeyGenerator>(*context);
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

Afseal::~Afseal(){};

// -----------------------------------------------------------------------------
// ------------------------------ CRYPTOGRAPHY ---------------------------------
// -----------------------------------------------------------------------------
// CONTEXT GENERATION
void Afseal::ContextGen(scheme_t scheme,
                        uint64_t poly_modulus_degree,
                        uint64_t plain_modulus_bit_size,
                        uint64_t plain_modulus,
                        int sec,
                        std::vector<int> qs)
{

  // BFV
  if (scheme == scheme_t::bfv)
  {
    EncryptionParameters parms(scheme_type::bfv);
    // Context generation
    parms.set_poly_modulus_degree(poly_modulus_degree);
    if (sec > 0)
    {
      parms.set_coeff_modulus(
          CoeffModulus::BFVDefault(poly_modulus_degree, static_cast<sec_level_type>(sec)));
    }
    else
    {
      parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, qs));
    }
    // parms.set_plain_modulus(plain_modulus); -> done automatically
    if (plain_modulus_bit_size > 0)
    {
      parms.set_plain_modulus(PlainModulus::Batching((size_t)poly_modulus_degree, (int)plain_modulus_bit_size));
    }
    else
    {
      parms.set_plain_modulus(plain_modulus);
    }
    this->context = make_shared<SEALContext>(parms);
    // Codec
    this->bfvEncoder = make_shared<BatchEncoder>(*context);
  }
  // CKKS
  else if (scheme == scheme_t::ckks)
  {
    EncryptionParameters parms(scheme_type::ckks);
    // Context generation
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, qs));
    this->context = make_shared<SEALContext>(parms);
    // Codec
    this->ckksEncoder = make_shared<CKKSEncoder>(*context);
  }
  else
  {
    throw invalid_argument("scheme must be bfv or ckks");
  }
  // Evaluator
  this->evaluator = make_shared<Evaluator>(*context);
  // Key generator
  this->keyGenObj = make_shared<KeyGenerator>(*context);
}

// KEY GENERATION
void Afseal::KeyGen()
{
  auto &context = *(this->get_context());
  // Key generator
  this->keyGenObj = make_shared<KeyGenerator>(context); // Refresh KeyGen obj
  this->publicKey = make_shared<PublicKey>();
  keyGenObj->create_public_key(*publicKey); // Extract keys
  this->secretKey = make_shared<SecretKey>(keyGenObj->secret_key());
  this->encryptor = make_shared<Encryptor>(context, *publicKey);
  this->decryptor = make_shared<Decryptor>(context, *secretKey);
}

void Afseal::relinKeyGen()
{
  if (keyGenObj == NULL)
  {
    throw std::logic_error("<Afseal>: Context not initialized");
  }
  this->relinKeys = std::make_shared<RelinKeys>();
  keyGenObj->create_relin_keys(*relinKeys);
}

void Afseal::rotateKeyGen()
{
  if (keyGenObj == NULL)
  {
    throw std::logic_error("<Afseal>: Context not initialized");
  }
  rotateKeys = make_shared<GaloisKeys>();
  keyGenObj->create_galois_keys(*rotateKeys);
}

// ENCRYPTION
void Afseal::encrypt(AfPtxt &plain1, AfCtxt &ctxt)
{
  this->get_encryptor()->encrypt(_dyn_p(plain1), _dyn_c(ctxt));
}
void Afseal::encrypt_v(std::vector<AfPtxt *> &plainV, std::vector<AfCtxt *> &ctxtVOut)
{
  auto encryptor = this->get_encryptor();
  vectorize(
      ctxtVOut, plainV,
      [encryptor](AfCtxt c, AfPtxt p)
      { encryptor->encrypt(_dyn_p(p), _dyn_c(c)); });
}

// DECRYPTION
void Afseal::decrypt(AfCtxt &ctxt, AfPtxt &ptxtOut)
{
  this->get_decryptor()->decrypt(_dyn_c(ctxt), _dyn_p(ptxtOut));
}
void Afseal::decrypt_v(std::vector<AfCtxt *> &ctxtV, std::vector<AfPtxt *> &plainVOut)
{
  auto decryptor = this->get_decryptor();
  vectorize(
      ctxtV, plainVOut,
      [decryptor](AfCtxt c, AfPtxt p)
      { decryptor->decrypt(_dyn_c(c), _dyn_p(p)); });
}

// NOISE MEASUREMENT
int Afseal::noise_level(AfCtxt &ctxt)
{
  return this->get_decryptor()->invariant_noise_budget(_dyn_c(ctxt));
}

// -----------------------------------------------------------------------------
// ---------------------------------- CODEC -----------------------------------
// -----------------------------------------------------------------------------
// ENCODE
// bfv
void Afseal::encode_i(vector<int64_t> &values, AfPtxt &ptxtOut)
{
  auto bfv_encoder = this->get_bfv_encoder();
  if (values.size() > bfv_encoder->slot_count())
  {
    throw range_error("<Afseal>: Data vector size is bigger than bfv nSlots");
  }
  bfvEncoder->encode(values, _dyn_p(ptxtOut));
}
// ckks
void Afseal::encode_f(vector<double> &values, double scale, AfPtxt &ptxtOut)
{
  auto ckks_encoder = this->get_ckks_encoder();
  if (values.size() > ckks_encoder->slot_count())
  {
    throw range_error("<Afseal>: Data vector size is bigger than ckks nSlots");
  }
  ckks_encoder->encode(values, scale, _dyn_p(ptxtOut));
}
void Afseal::encode_c(std::vector<complex<double>> &values, double scale, AfPtxt &ptxtOut)
{
  auto ckks_encoder = this->get_ckks_encoder();
  if (values.size() > ckks_encoder->slot_count())
  {
    throw range_error("<Afseal>: Data vector size is bigger than ckks nSlots");
  }
  ckks_encoder->encode(values, scale, _dyn_p(ptxtOut));
}

// DECODE
// bfv
void Afseal::decode_i(AfPtxt &plain1, std::vector<int64_t> &valueVOut)
{
  this->get_bfv_encoder()->decode(_dyn_p(plain1), valueVOut);
}
// ckks
void Afseal::decode_f(AfPtxt &plain1, vector<double> &valueVOut)
{
  this->get_ckks_encoder()->decode(_dyn_p(plain1), valueVOut);
}
void Afseal::decode_c(AfPtxt &plain1, vector<std::complex<double>> &valueVOut)
{
  this->get_ckks_encoder()->decode(_dyn_p(plain1), valueVOut);
}

// AUXILIARY
void Afseal::data(AfPtxt &ptxt, uint64_t *dest)
{
  dest = _dyn_p(ptxt).data();
}

// void Afseal::allocate_zero_poly(uint64_t n, uint64_t coeff_mod_count, uint64_t *dest) {
//   dest = &util::allocate_zero_poly(n, coeff_mod_count, pool)[0]; --> pool?
// }

// ------------------------------ RELINEARIZATION -----------------------------
void Afseal::relinearize(AfCtxt &ctxt)
{
  this->get_evaluator()->relinearize_inplace(_dyn_c(ctxt), *(this->get_relinKeys()));
}
void Afseal::relinearize_v(vector<AfCtxt *> ctxtV)
{
  auto ev = this->get_evaluator();
  seal::RelinKeys &rlk = *(this->get_relinKeys());
  vectorize(ctxtV,
            [ev, rlk](AfCtxt c)
            { ev->relinearize_inplace(_dyn_c(c), rlk); });
}

// -----------------------------------------------------------------------------
// --------------------------------- OPERATIONS --------------------------------
// -----------------------------------------------------------------------------
// NEGATE
void Afseal::negate(AfCtxt &ctxt)
{
  this->get_evaluator()->negate_inplace(_dyn_c(ctxt));
}
void Afseal::negate_v(vector<AfCtxt *> &ctxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtV,
            [ev](AfCtxt c)
            { ev->negate_inplace(_dyn_c(c)); });
}

// SQUARE
void Afseal::square(AfCtxt &ctxt)
{
  this->get_evaluator()->square_inplace(_dyn_c(ctxt));
}
void Afseal::square_v(vector<AfCtxt *> &ctxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtV,
            [ev](AfCtxt c)
            { ev->square_inplace(_dyn_c(c)); });
}

// ADDITION
void Afseal::add(AfCtxt &cipherInOut, AfCtxt &cipher2)
{
  this->get_evaluator()->add_inplace(_dyn_c(cipherInOut), _dyn_c(cipher2));
}
void Afseal::add_plain(AfCtxt &cipherInOut, AfPtxt &plain2)
{
  this->get_evaluator()->add_plain_inplace(_dyn_c(cipherInOut), _dyn_p(plain2));
}
void Afseal::cumsum(AfCtxt &cipherInOut)
{
  auto ev = this->get_evaluator();
  AfCtxt cipherAux = cipherInOut;
  int k = 1;
  for (int i = 0; i < this->get_nRots(); i++)
  {
    rotate(cipherAux, k);
    ev->add_inplace(_dyn_c(cipherInOut), _dyn_c(cipherAux));
    k = k << 1;
  }
}
void Afseal::add_v(vector<AfCtxt *> &ctxtVInOut, vector<AfCtxt *> &ctxtV2)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ctxtV2,
            [ev](AfCtxt c, AfCtxt c2)
            { ev->add_inplace(_dyn_c(c), _dyn_c(c2)); });
}
void Afseal::add_plain_v(vector<AfCtxt *> &ctxtVInOut, vector<AfPtxt *> &ptxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ptxtV,
            [ev](AfCtxt c, AfPtxt p2)
            { ev->add_plain_inplace(_dyn_c(c), _dyn_p(p2)); });
}
void Afseal::cumsum_v(vector<AfCtxt *> &ctxtVIn, AfCtxt &cipherOut)
{
  auto ev = this->get_evaluator();
  // TODO: omp reduce
  // #pragma omp parallel for reduction(+ : cipherOut)
  for (auto c1 = ctxtVIn.begin(); c1 != ctxtVIn.end(); c1++)
  {
    ev->add_inplace(_dyn_c(cipherOut), _dyn_c(**c1));
  }
}

// SUBTRACTION
void Afseal::sub(AfCtxt &cipherInOut, AfCtxt &cipher2)
{
  this->get_evaluator()->sub_inplace(_dyn_c(cipherInOut), _dyn_c(cipher2));
}
void Afseal::sub_plain(AfCtxt &cipherInOut, AfPtxt &plain2)
{
  this->get_evaluator()->sub_plain_inplace(_dyn_c(cipherInOut), _dyn_p(plain2));
}
void Afseal::sub_v(vector<AfCtxt *> &ctxtVInOut, vector<AfCtxt *> &ctxtV2)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ctxtV2,
            [ev](AfCtxt c, AfCtxt c2)
            { ev->sub_inplace(_dyn_c(c), _dyn_c(c2)); });
}
void Afseal::sub_plain_v(vector<AfCtxt *> &ctxtVInOut, vector<AfPtxt *> &ptxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ptxtV,
            [ev](AfCtxt c, AfPtxt p2)
            { ev->sub_plain_inplace(_dyn_c(c), _dyn_p(p2)); });
}

// MULTIPLICATION
void Afseal::multiply(AfCtxt &cipherInOut, AfCtxt &cipher2)
{
  this->get_evaluator()->multiply_inplace(_dyn_c(cipherInOut), _dyn_c(cipher2));
}
void Afseal::multiply_plain(AfCtxt &cipherInOut, AfPtxt &plain1)
{
  this->get_evaluator()->multiply_plain_inplace(_dyn_c(cipherInOut), _dyn_p(plain1));
}
void Afseal::multiply_v(vector<AfCtxt *> &ctxtVInOut, vector<AfCtxt *> &ctxtV2)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ctxtV2,
            [ev](AfCtxt c, AfCtxt c2)
            { ev->multiply_inplace(_dyn_c(c), _dyn_c(c2)); });
}
void Afseal::multiply_plain_v(vector<AfCtxt *> &ctxtVInOut, vector<AfPtxt *> &ptxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtVInOut, ptxtV,
            [ev](AfCtxt c, AfPtxt p2)
            { ev->multiply_plain_inplace(_dyn_c(c), _dyn_p(p2)); });
}

// ROTATION
void Afseal::rotate(AfCtxt &ctxt, int &k)
{
  if (this->get_scheme() == scheme_t::bfv)
  {
    this->get_evaluator()->rotate_rows_inplace(_dyn_c(ctxt), k, *(this->get_rotateKeys()));
  }
  else if (this->get_scheme() == scheme_t::ckks)
  {
    this->get_evaluator()->rotate_vector_inplace(_dyn_c(ctxt), k, *(this->get_rotateKeys()));
  }
  else
  {
    throw std::logic_error("<Afseal>: Scheme not supported for rotation");
  }
}
void Afseal::rotate_v(vector<AfCtxt *> &ctxtV, int &k)
{
  auto ev = this->get_evaluator();
  auto &rtk = *(this->get_rotateKeys());
  if (this->get_scheme() == scheme_t::bfv)
  {
    vectorize(ctxtV,
              [ev, k, rtk](AfCtxt c)
              { ev->rotate_rows_inplace(_dyn_c(c), k, rtk); });
  }
  else if (this->get_scheme() == scheme_t::ckks)
  {
    vectorize(ctxtV,
              [ev, k, rtk](AfCtxt c)
              { ev->rotate_vector_inplace(_dyn_c(c), k, rtk); });
  }
  else
  {
    throw std::logic_error("<Afseal>: Scheme not supported for rotation");
  }
}
void Afseal::flip(AfCtxt &ctxt)
{
  if (this->get_scheme() == scheme_t::bfv)
  {
    this->get_evaluator()->rotate_columns_inplace(_dyn_c(ctxt), *(this->get_rotateKeys()));
  }
  else
  {
    throw std::logic_error("<Afseal>: Only bfv scheme supports column rotation");
  }
}
void Afseal::flip_v(vector<AfCtxt *> &ctxtV)
{
  auto ev = this->get_evaluator();
  auto &rtk = *(this->get_rotateKeys());
  if (this->get_scheme() == scheme_t::bfv)
  {
    vectorize(ctxtV,
              [ev, rtk](AfCtxt c)
              { ev->rotate_columns_inplace(_dyn_c(c), rtk); });
  }
  else
  {
    throw std::logic_error("<Afseal>: Only bfv scheme supports column rotation");
  }
}

// POLYNOMIALS
void Afseal::exponentiate(AfCtxt &ctxt, uint64_t &expon)
{
  this->get_evaluator()->exponentiate_inplace(_dyn_c(ctxt), expon, *relinKeys);
}
void Afseal::exponentiate_v(vector<AfCtxt *> &ctxtV, uint64_t &expon)
{
  auto ev = this->get_evaluator();
  auto &rlk = *(this->get_relinKeys());
  vectorize(ctxtV,
            [ev, expon, rlk](AfCtxt c)
            { ev->exponentiate_inplace(_dyn_c(c), expon, rlk); });
}

// CKKS -> Rescaling and mod switching
void Afseal::rescale_to_next(AfCtxt &ctxt)
{
  if (this->get_scheme() == scheme_t::ckks)
  {
    this->get_evaluator()->rescale_to_next_inplace(_dyn_c(ctxt));
  }
  else
  {
    throw std::logic_error("<Afseal>: Scheme must be ckks");
  }
}
void Afseal::rescale_to_next_v(vector<AfCtxt *> &ctxtV)
{
  auto ev = this->get_evaluator();
  if (this->get_scheme() == scheme_t::ckks)
  {
    vectorize(ctxtV,
              [ev](AfCtxt c)
              { ev->rescale_to_next_inplace(_dyn_c(c)); });
  }
  else
  {
    throw std::logic_error("<Afseal>: Scheme must be ckks");
  }
}

void Afseal::mod_switch_to_next(AfCtxt &ctxt)
{
  this->get_evaluator()->mod_switch_to_next_inplace(_dyn_c(ctxt));
}
void Afseal::mod_switch_to_next_v(vector<AfCtxt *> &ctxtV)
{
  auto ev = this->get_evaluator();
  vectorize(ctxtV,
            [ev](AfCtxt c)
            { ev->mod_switch_to_next_inplace(_dyn_c(c)); });
}

void Afseal::mod_switch_to_next_plain(AfPtxt &ptxt)
{
  this->get_evaluator()->mod_switch_to_next_inplace(_dyn_p(ptxt));
}
void Afseal::mod_switch_to_next_plain_v(vector<AfPtxt *> &plainV)
{
  auto ev = this->get_evaluator();
  vectorize(plainV,
            [ev](AfPtxt p)
            { ev->mod_switch_to_next_inplace(_dyn_p(p)); });
}

// -----------------------------------------------------------------------------
// ------------------------------------- I/O -----------------------------------
// -----------------------------------------------------------------------------
// SAVE/LOAD CONTEXT
size_t Afseal::save_context(ostream &out_stream, string &compr_mode)
{
  return (size_t)this->get_context()->key_context_data()->parms().save(
      out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_context(istream &in_stream)
{
  EncryptionParameters parms;
  size_t loaded_bytes = (size_t)parms.load(in_stream);
  this->context = make_shared<SEALContext>(parms);
  if (parms.scheme() == scheme_type::bfv)
  {
    this->bfvEncoder = make_shared<BatchEncoder>(*context);
  }
  else if (parms.scheme() == scheme_type::ckks)
  {
    this->ckksEncoder = make_shared<CKKSEncoder>(*context);
  }
  this->evaluator = make_shared<Evaluator>(*context);
  this->keyGenObj = make_shared<KeyGenerator>(*context);
  return loaded_bytes;
}

// SAVE/LOAD PUBLICKEY
size_t Afseal::save_public_key(ostream &out_stream, string &compr_mode)
{
  return (size_t)this->get_publicKey()->save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_public_key(istream &in_stream)
{
  seal::SEALContext &context = *(this->get_context());
  this->publicKey = make_shared<PublicKey>();
  size_t loaded_bytes = (size_t)publicKey->load(context, in_stream);
  this->encryptor = make_shared<Encryptor>(context, *publicKey);
  return loaded_bytes;
}

// SAVE/LOAD SECRETKEY
size_t Afseal::save_secret_key(ostream &out_stream, string &compr_mode)
{
  return (size_t)this->get_secretKey()->save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_secret_key(istream &in_stream)
{
  seal::SEALContext &context = *(this->get_context());
  this->secretKey = make_shared<SecretKey>();
  size_t loaded_bytes = (size_t)secretKey->load(context, in_stream);
  this->decryptor = make_shared<Decryptor>(context, *secretKey);
  return loaded_bytes;
}

// SAVE/LOAD RELINKEY
size_t Afseal::save_relin_keys(ostream &out_stream, string &compr_mode)
{
  return (size_t)this->get_relinKeys()->save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_relin_keys(istream &in_stream)
{
  this->relinKeys = make_shared<RelinKeys>();
  return (size_t)relinKeys->load(*(this->get_context()), in_stream);
}

// SAVE/LOAD ROTKEYS
size_t Afseal::save_rotate_keys(ostream &out_stream, string &compr_mode)
{
  return (size_t)this->get_rotateKeys()->save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_rotate_keys(istream &in_stream)
{
  this->rotateKeys = make_shared<GaloisKeys>();
  return (size_t)rotateKeys->load(*(this->get_context()), in_stream);
}

// SAVE/LOAD PLAINTEXT --> Could be achieved outside of Afseal
size_t Afseal::save_plaintext(ostream &out_stream, string &compr_mode, AfPtxt &plain)
{
  return (size_t)_dyn_p(plain).save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_plaintext(istream &in_stream, AfPtxt &plain)
{
  return (size_t)_dyn_p(plain).load(*context, in_stream);
}

// SAVE/LOAD CIPHERTEXT --> Could be achieved outside of Afseal
size_t Afseal::save_ciphertext(ostream &out_stream, string &compr_mode, AfCtxt &ciphert)
{
  return (size_t)_dyn_c(ciphert).save(out_stream, compr_mode_map[compr_mode]);
}
size_t Afseal::load_ciphertext(istream &in_stream, AfCtxt &plain)
{
  return (size_t)_dyn_c(plain).load(*context, in_stream);
}

// -----------------------------------------------------------------------------
// -------------------------------- AUXILIARY ----------------------------------
// -----------------------------------------------------------------------------
bool Afseal::batchEnabled()
{
  return this->get_context()->first_context_data()->qualifiers().using_batching;
}
long Afseal::maxBitCount(long poly_modulus_degree, int sec_level)
{
  std::map<int, sec_level_type> sec_map{
      {128, sec_level_type::tc128},
      {192, sec_level_type::tc192},
      {256, sec_level_type::tc256},
  };
  return CoeffModulus::MaxBitCount(poly_modulus_degree, sec_map[sec_level]);
}
double Afseal::scale(AfCtxt &ctxt)
{
  return _dyn_c(ctxt).scale();
}
void Afseal::override_scale(AfCtxt &ctxt, double scale)
{
  _dyn_c(ctxt).scale() = scale;
}
int Afseal::get_sec()
{
  return static_cast<std::underlying_type<sec_level_type>::type>(
      this->get_context()->first_context_data()->qualifiers().sec_level);
}
// GETTERS
shared_ptr<SEALContext> inline Afseal::get_context()
{
  if (this->context == NULL)
  {
    throw std::logic_error("<Afseal>: Context not initialized");
  }
  return (this->context);
}
shared_ptr<Evaluator> inline Afseal::get_evaluator()
{
  if (this->evaluator == NULL)
  {
    throw std::logic_error("<Afseal>: Context not initialized");
  }
  return (this->evaluator);
}
shared_ptr<Encryptor> inline Afseal::get_encryptor()
{
  if (this->encryptor == NULL)
  {
    throw std::logic_error("<Afseal>: Missing Public key");
  }
  return (this->encryptor);
}
shared_ptr<Decryptor> inline Afseal::get_decryptor()
{
  if (this->encryptor == NULL)
  {
    throw std::logic_error("<Afseal>: Missing Public key");
  }
  return (this->decryptor);
}
shared_ptr<BatchEncoder> inline Afseal::get_bfv_encoder()
{
  if (this->encryptor == NULL)
  {
    throw std::logic_error("<Afseal>: BFV context not initialized");
  }
  return (this->bfvEncoder);
}
shared_ptr<CKKSEncoder> inline Afseal::get_ckks_encoder()
{
  if (this->encryptor == NULL)
  {
    throw std::logic_error("<Afseal>: CKKS context not initialized");
  }
  return (this->ckksEncoder);
}
shared_ptr<SecretKey> inline Afseal::get_secretKey()
{
  if (this->secretKey == NULL)
  {
    throw std::logic_error("<Afseal>: Secret Key not initialized");
  }
  return (this->secretKey);
}
shared_ptr<PublicKey> inline Afseal::get_publicKey()
{
  if (this->publicKey == NULL)
  {
    throw std::logic_error("<Afseal>: Public Key not initialized");
  }
  return (this->publicKey);
}
shared_ptr<RelinKeys> inline Afseal::get_relinKeys()
{
  if (this->relinKeys == NULL)
  {
    throw std::logic_error("<Afseal>: Relinearization Keys not initialized");
  }
  return (this->relinKeys);
}
shared_ptr<GaloisKeys> inline Afseal::get_rotateKeys()
{
  if (this->rotateKeys == NULL)
  {
    throw std::logic_error("<Afseal>: Rotation Keys not initialized");
  }
  return (this->rotateKeys);
}
size_t Afseal::get_nSlots()
{
  scheme_t scheme = this->get_scheme();
  if (scheme == scheme_t::bfv)
  {
    if (this->bfvEncoder == NULL)
    {
      throw std::logic_error("<Afseal>: Context not initialized with BFV scheme");
    }
    return this->bfvEncoder->slot_count();
  }
  else if (scheme == scheme_t::ckks)
  {
    if (this->ckksEncoder == NULL)
    {
      throw std::logic_error("<Afseal>: Context not initialized with CKKS scheme");
    }
    return this->ckksEncoder->slot_count();
  }
  return -1;
}
int Afseal::get_nRots()
{
  int nSlots = (int)this->get_poly_modulus_degree() / 2, nRots = 0;
  while (nSlots > 0)
  {
    nSlots = nSlots >> 1;
    nRots++;
  };
  return nRots - 1;
}
uint64_t Afseal::get_plain_modulus()
{
  return this->get_context()->first_context_data()->parms().plain_modulus().value();
}
size_t Afseal::get_poly_modulus_degree()
{
  return this->get_context()->first_context_data()->parms().poly_modulus_degree();
}

scheme_t Afseal::get_scheme()
{
  return scheme_map[this->get_context()->first_context_data()->parms().scheme()];
}

int Afseal::total_coeff_modulus_bit_count()
{
  return this->get_context()->first_context_data()->total_coeff_modulus_bit_count();
}
// TODO: coeff_modulus?

// -----------------------------------------------------------------------------
// ----------------------------- VECTORIZATION ---------------------------------
// -----------------------------------------------------------------------------
void Afseal::vectorize(
    vector<AfCtxt *> &ctxtVInOut,
    vector<AfCtxt *> &ctxtV2,
    function<void(AfCtxt, AfCtxt)> f)
{
  if (ctxtVInOut.size() != ctxtV2.size())
  {
    throw runtime_error("Vectors must be of same size to vectorize");
  }
#pragma omp parallel for
  for (int i = 0; i < (int)ctxtVInOut.size(); i++)
  {
    f(_dyn_c(*ctxtVInOut[i]), _dyn_c(*ctxtV2[i]));
  }
}
void Afseal::vectorize(
    vector<AfCtxt *> &ctxtVInOut,
    vector<AfPtxt *> &ptxtV,
    function<void(AfCtxt, AfPtxt)> f)
{
  if (ctxtVInOut.size() != ptxtV.size())
  {
    throw runtime_error("Vectors must be of same size to vectorize");
  }
#pragma omp parallel for
  for (int i = 0; i < (int)ctxtVInOut.size(); i++)
  {
    f(_dyn_c(*ctxtVInOut[i]), _dyn_p(*ptxtV[i]));
  }
}

void Afseal::vectorize(
    vector<AfCtxt *> &ctxtVInOut,
    function<void(AfCtxt)> f)
{
#pragma omp parallel for
  for (int i = 0; i < (int)ctxtVInOut.size(); i++)
  {
    f(_dyn_c(*ctxtVInOut[i]));
  }
}

void Afseal::vectorize(
    vector<AfPtxt *> &plainVInOut,
    function<void(AfPtxt)> f)
{
#pragma omp parallel for
  for (int i = 0; i < (int)plainVInOut.size(); i++)
  {
    f(_dyn_p(*plainVInOut[i]));
  }
}

// -----------------------------------------------------------------------------
// ------------------------------ POLYNOMIALS ----------------------------------
// -----------------------------------------------------------------------------
void Afseal::add_inplace(AfPoly &p1, AfPoly &p2)
{
  dynamic_cast<AfsealPoly &>(p1).add_inplace(dynamic_cast<AfsealPoly &>(p2));
}

void Afseal::subtract_inplace(AfPoly &p1, AfPoly &p2)
{
  dynamic_cast<AfsealPoly &>(p1).subtract_inplace(dynamic_cast<AfsealPoly &>(p2));
}

void Afseal::multiply_inplace(AfPoly &p1, AfPoly &p2)
{
  dynamic_cast<AfsealPoly &>(p1).multiply_inplace(dynamic_cast<AfsealPoly &>(p2));
}

void Afseal::invert_inplace(AfPoly &poly)
{
  if (!dynamic_cast<AfsealPoly &>(poly).invert_inplace())
  {
    // TODO: How to communicate this information without throwing an exception?
    throw runtime_error("<Afseal>: Inverse does not exist.");
  }
}

void Afseal::poly_to_ciphertext(AfPoly &p, AfCtxt &ctxt, size_t i)
{
  // TODO: This shouldn't be too hard, just copy into position,
  //  but we need to ensure the sizes match,
  //  allocate a zero poly if the index doesn't exist, etc
  throw runtime_error("<Afseal>: Not yet implemented.");
}

void Afseal::poly_to_plaintext(AfPoly &p, AfPtxt &ptxt)
{
  // TODO: This shouldn't be too hard, just copy into position,
  //  but we need to ensure the sizes match,
  //  allocate a zero poly if the poly doesn't yet exist, etc
  throw runtime_error("<Afseal>: Not yet implemented.");
}

std::complex<double> Afseal::get_coeff(AfPoly &poly, size_t i)
{
  return poly.get_coeff(*this, i);
}

void Afseal::set_coeff(AfPoly &poly, complex<double> &val, size_t i)
{
  dynamic_cast<AfsealPoly &>(poly).set_coeff(*this, val, i);
}

std::vector<std::complex<double>> Afseal::to_coeff_list(AfPoly &poly)
{
  return dynamic_cast<AfsealPoly &>(poly).to_coeff_list(*this);
}

AfsealPoly Afseal::get_publicKey_poly(size_t index)
{
  if (this->publicKey == NULL)
  {
    throw std::logic_error("<Afseal>: Public Key not initialized");
  }
  return AfsealPoly(*this, static_cast<AfsealCtxt &>(this->publicKey->data()), index);
}

AfsealPoly Afseal::get_secretKey_poly()
{
  if (this->secretKey == NULL)
  {
    throw std::logic_error("<Afseal>: Secret Key not initialized");
  }
  return AfsealPoly(*this, static_cast<AfsealPtxt &>(this->secretKey->data()));
}

// =============================================================================
// ================================ AFSEALPOLY =================================
// =============================================================================

/// Internally, seal stores the polynomials of a ctxt as DynArray<uint64_t>,
/// i.e., linear arrays of size ctxt.size * ctxt.poly_modulus_degree * ctxt.coeff_modulus_size

// ----------------------------- CLASS MANAGEMENT -----------------------------

AfsealPoly::AfsealPoly(Afseal &afseal) : parms_id(afseal.context->first_parms_id()),
                                         mempool(seal::MemoryManager::GetPool()),
                                         coeff_count(afseal.context->first_context_data()->parms().poly_modulus_degree()),
                                         coeff_modulus(afseal.context->first_context_data()->parms().coeff_modulus()),
                                         coeff_modulus_count(afseal.context->first_context_data()->parms().coeff_modulus().size())
{
  eval_repr.resize(coeff_count * coeff_modulus_count, true);
}

AfsealPoly::AfsealPoly(Afseal &afseal, const AfsealCtxt &ref)
    : parms_id(ref.parms_id()), mempool(seal::MemoryManager::GetPool()),
      coeff_count(ref.poly_modulus_degree()),
      coeff_modulus(afseal.context->get_context_data(parms_id)->parms().coeff_modulus()),
      coeff_modulus_count(afseal.context->get_context_data(parms_id)->parms().coeff_modulus().size())
{

  eval_repr.resize(coeff_count * coeff_modulus_count, true);
}

AfsealPoly::AfsealPoly(Afseal &afseal, AfsealCtxt &ctxt, size_t index)
    : parms_id(ctxt.parms_id()), mempool(seal::MemoryManager::GetPool()),
      coeff_count(ctxt.poly_modulus_degree()),
      coeff_modulus(afseal.context->get_context_data(parms_id)->parms().coeff_modulus()),
      coeff_modulus_count(afseal.context->get_context_data(parms_id)->parms().coeff_modulus().size())
{

  // Copy coefficients from ctxt
  if (ctxt.is_ntt_form())
  {
    eval_repr.resize(coeff_count * coeff_modulus_count);
    for (size_t i = 0; i < coeff_count * coeff_modulus_count; ++i)
    {
      eval_repr[i] = *(ctxt.data(index) + i);
    }
  }
  else
  {
    // TODO: Think about supporting this?
    throw runtime_error("<Afseal>: Not yet implemented.");
  }
}

AfsealPoly::AfsealPoly(Afseal &afseal, AfsealPtxt &ptxt) : parms_id(ptxt.parms_id()),
                                                           mempool(seal::MemoryManager::GetPool()),
                                                           coeff_count(ptxt.coeff_count()),
                                                           coeff_modulus(afseal.context->get_context_data(parms_id)
                                                                             ->parms()
                                                                             .coeff_modulus()),
                                                           coeff_modulus_count(afseal.context
                                                                                   ->get_context_data(parms_id)
                                                                                   ->parms()
                                                                                   .coeff_modulus()
                                                                                   .size())
{

  if (ptxt.is_ntt_form())
  {
    eval_repr.resize(coeff_count * coeff_modulus_count);
    for (size_t i = 0; i < coeff_count * coeff_modulus_count; ++i)
    {
      eval_repr[i] = *(ptxt.data() + i);
    }
  }
  else
  {
    // TODO: Think about supporting this?
    throw runtime_error("<Afseal>: Not yet implemented.");
  }
}

AfsealPoly::~AfsealPoly(){};

// -------------------------------- COEFFICIENTS -------------------------------
void AfsealPoly::generate_coeff_repr(Afseal &afseal)
{
  if (!coeff_repr_valid)
  {

    // Resize the coeff_repr

    // Copy the coefficients over
    coeff_repr = eval_repr;

    // Now do the actual conversion
    auto small_ntt_tables = afseal.context->get_context_data(parms_id)->small_ntt_tables();
#pragma omp parallel for
    for (int j = 0; j < coeff_modulus_count; j++)
    {
      util::inverse_ntt_negacyclic_harvey(coeff_repr.begin() + (j * coeff_count), small_ntt_tables[j]); // non-ntt form
    }

    // set valid flag
    coeff_repr_valid = true;
  }
}

std::vector<std::complex<double>> AfsealPoly::to_coeff_list(Afhel &afhel)
{
  generate_coeff_repr(dynamic_cast<Afseal &>(afhel));
  // TODO: Need to also decompose the CRT representation
  //  and then do some more magic!
  throw runtime_error("<Afseal>: Not yet implemented.");
}

std::complex<double> AfsealPoly::get_coeff(Afhel &afhel, size_t i)
{
  return to_coeff_list(afhel)[i];
}

void AfsealPoly::set_coeff(Afhel &afhel, std::complex<double> &val, size_t i)
{
  auto v = to_coeff_list(afhel);
  v[i] = val;
  // TODO: Convert vector back into CRT, then apply NTT
  //  don't forget to also write the coeff_repr and set the valid bit,
  //  since we already have the data around!
  throw runtime_error("<Afseal>: Not yet implemented.");
}

// -------------------------------- OPERATIONS ---------------------------------
void AfsealPoly::add_inplace(const AfPoly &other)
{
#pragma omp parallel for
  for (int j = 0; j < (int)coeff_modulus.size(); j++)
  {
    util::add_poly_coeffmod(&eval_repr[j * coeff_count],
                            &dynamic_cast<const AfsealPoly &>(other).eval_repr[j * coeff_count],
                            coeff_count,
                            coeff_modulus[j],
                            &eval_repr[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

void AfsealPoly::subtract_inplace(const AfPoly &other)
{
#pragma omp parallel for
  for (int j = 0; j < (int)coeff_modulus.size(); j++)
  {
    util::sub_poly_coeffmod(&eval_repr[j * coeff_count],
                            &dynamic_cast<const AfsealPoly &>(other).eval_repr[j * coeff_count],
                            coeff_count,
                            coeff_modulus[j],
                            &eval_repr[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

void AfsealPoly::multiply_inplace(const AfPoly &other)
{
  const AfsealPoly *o_p = dynamic_cast<const AfsealPoly *>(&other);
#pragma omp parallel for
  for (int j = 0; j < (int)coeff_modulus.size(); j++)
  {
    util::dyadic_product_coeffmod(&eval_repr[j * coeff_count],
                                  &(*o_p).eval_repr[j * coeff_count],
                                  coeff_count,
                                  coeff_modulus[j],
                                  &eval_repr[j * coeff_count]); // TODO: Check if this is safe (used to be result + ..)
  }
  // invalidate the coeff_repr
  coeff_repr_valid = false;
}

bool AfsealPoly::invert_inplace()
{
  // compute a^{-1}, where a is a double-CRT polynomial whose evaluation representation
  // is in a. The double-CRT representation in SEAL is stored as a flat array of
  // length coeff_count * modulus_count:
  //    [ 0 .. coeff_count-1 , coeff_count .. 2*coeff_count-1, ... ]
  //      ^--- a (mod p0)    , ^--- a (mod p1),              ,  ...
  // return if the inverse exists, and result is also in evaluation representation

  bool *has_inv = new bool[coeff_modulus_count];
  fill_n(has_inv, coeff_modulus_count, true);
#pragma omp parallel for
  for (int j = 0; j < coeff_modulus_count; j++)
  {
    for (size_t i = 0; i < coeff_count && has_inv[j]; i++)
    {
      uint64_t inv = 0;
      if (util::try_invert_uint_mod(eval_repr[i + (j * coeff_count)], coeff_modulus[j], inv))
      {
        eval_repr[i + (j * coeff_count)] = inv; // TODO: Check if this is safe (used to be result[...])
      }
      else
      {
        has_inv[j] = false;
      }
    }
  }
  for (int j = 0; j < (int)coeff_modulus.size(); j++)
  {
    // invalidate the coeff_repr
    coeff_repr_valid = false;
    if (!has_inv[j])
      return false;
  }
  delete[] has_inv;

  // invalidate the coeff_repr
  coeff_repr_valid = false;

  return true;
}
