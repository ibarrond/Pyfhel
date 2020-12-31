#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include <NTL/lzz_pXFactoring.h>

#include "Afhel/Afhel.h"

#include <cassert>
#include <cstdio>

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
    /*
    long p = 2;
    long r = 1;
    long d = 1;
    long c = 2;
    long sec = 80;
    long w = 64;
    long L = 10;
    */
    // Store & retrieve environment
    he.restoreEnv(fileName);

    vector<long> v1;
    vector<long> v2;
    for(int i=0; i<he.nslots; i++){v1.push_back(i);}
    for(int i=0; i<he.nslots; i++){v2.push_back(2);}

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

    std::cout << "END OF DEMO" << endl;
};

