/* Copyright (C) 2012-2017 IBM Corp.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

/* Test_IO.cpp - Testing the I/O of the important classes of the library
 * (context, keys, ciphertexts).
 */
#include <fstream>
#include <unistd.h>

#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"

#define N_TESTS 1
static long ms[N_TESTS][10] = {
  //nSlots  m   phi(m) ord(2)
  {   2,    7,    6,    3,   0,0,0,0,0,0},
};

void checkCiphertext(const Ctxt& ctxt, const ZZX& ptxt, const FHESecKey& sk);

// Testing the I/O of the important classes of the library
// (context, keys, ciphertexts).
int main(int argc, char *argv[])
{  
  long m=7;  
  long r=1;
  long p=2;
  long c = 2;
  long w = 64;
  long L = 5;

  long ptxtSpace = power_long(p,r);

  FHEcontext* context;
  FHESecKey*  secretKey;
  Ctxt*       ctxt;
  EncryptedArray* ea;
  vector<ZZX> ptxt;

  // first loop: generate stuff and write it to cout

  // open file for writing
    fstream keyFile("iotest.txt", fstream::out|fstream::trunc);
    assert(keyFile.is_open());

    cout << "Testing IO: m="<<m<<", p^r="<<p<<"^"<<r<<endl;

    context = new FHEcontext(m, p, r);
    buildModChain(*context, L, c);  // Set the modulus chain

    // Output the FHEcontext to file
    secretKey = new FHESecKey(*context);
    const FHEPubKey& publicKey = *secretKey;
    secretKey->GenSecKey(w, ptxtSpace); // A Hamming-weight-w secret key
    addSome1DMatrices(*secretKey);// compute key-switching matrices that we need
    ea = new EncryptedArray(*context);
    long nslots = ea->size();

    // Output the secret key to file, twice. Below we will have two copies
    // of most things.
    writeContextBase(keyFile, *context);
    keyFile << *context << endl;
    keyFile << *secretKey << endl;
    keyFile.close();
    cerr << "so far, so good\n";

  // second loop: read from input and repeat the computation
  // open file for read
    keyFile.open("iotest.txt", fstream::in);
    cerr << "file reopened \n";
    // Read context from file
    unsigned long m1, p1, r1;
    vector<long> gens, ords;
    readContextBase(keyFile, m1, p1, r1, gens, ords);
    FHEcontext context2(m1, p1, r1, gens, ords);
    keyFile >> context2;
    assert (*context == context2);
    cerr << ": context matches input\n";

    // We define some things below wrt *contexts[i], not tmpContext.
    // This is because the various operator== methods check equality of
    // references, not equality of the referenced FHEcontext objects.
    FHESecKey secretKey2(context2);

    cerr << "POINTER FOR OK CODE \n";
    keyFile >> secretKey2;
    const FHEPubKey& publicKey2 = secretKey2;
    context = &context2;
    secretKey3 = &secretKey2;
    assert(*secretKey3 == *secretKey);
    cerr << "   secret key matches input\n";
  
  //unlink("iotest.txt"); // clean up before exiting
}

