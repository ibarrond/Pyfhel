#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include <FHE.h>
#include <timing.h>
#include <EncryptedArray.h>
#include <NTL/lzz_pXFactoring.h>

#include <Afhel.h>

#include <cassert>
#include <cstdio>
#define VECTOR_SIZE 5

int main(int argc, char **argv)
{
    string fileName = "DemoAfhelEnv";
    Afhel he;
    he.flagPrint = true;    // Enable print for all functions
    // Values for the modulus p (size of p):
    //   - 2 (Binary)
    //   - 257 (Byte)
    //   - 65537 (Word)
    //   - 4294967311 (Long) 
    long p = 2;
    long r = 32;
    long d = 1;
    long c = 2;
    long sec = 128;
    long w = 64;
    long L = 40;

    he.keyGen(p, r, c, d, sec, w, L);
    vector<long> v1;
    vector<long> v2;
    for(int i=0; i<he.nslots; i++){
        if(i<VECTOR_SIZE)   { v1.push_back(i);  }
        else                { v1.push_back(0);  }}
    for(int i=0; i<he.nslots; i++){
        if(i<VECTOR_SIZE)   { v2.push_back(2);  }
        else                { v2.push_back(0);  }}

    // Sum
    string k1 = he.encrypt(v1);
    string k2 = he.encrypt(v2);
    he.add(k1, k2);
    vector<long> vRes = he.decrypt(k1);
 

    // Multiplication
    k1 = he.encrypt(v1);
    k2 = he.encrypt(v2);
    he.mult(k1, k2);
    vector<long> vRes2 = he.decrypt(k1);

    // Scalar product
    k1 = he.encrypt(v1);
    k2 = he.encrypt(v2);
    he.scalarProd(k1, k2);
    vector<long> vRes3 = he.decrypt(k1);

    // Square
    k1 = he.encrypt(v1);
    he.square(k1);
    vector<long> vRes4 = he.decrypt(k1);

    // Store & retrieve environment
    he.saveEnv(fileName);
    std::cout << "Saved env with values: m=" << he.getM() <<
        ", p=" << he.getP() << ", r=" << he.getR() << endl;
    std::cout << "END OF DEMO" << endl;
};

