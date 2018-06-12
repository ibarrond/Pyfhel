#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include <helib/FHE.h>
#include <helib/timing.h>
#include <helib/EncryptedArray.h>
#include <NTL/lzz_pXFactoring.h>

#include <Afseal.h>

#include <cassert>
#include <cstdio>
#define VECTOR_SIZE 5

int main(int argc, char **argv)
{
    string fileName = "DemoAfsealEnv";
    Afseal he;
    // Values for the modulus p (size of p):
    //   - 2 (Binary)
    //   - 257 (Byte)
    //   - 65537 (Word)
    //   - 4294967311 (Long) 
    long p = 2;
    long m = 4096;
    long base = 2;
    long sec = 192;
	
	std::cout << " Afseal - Creating Context" << endl;
	he.ContextGen(p, m, base, sec);
	std::cout << " Afseal - Context CREATED" << endl;


	std::cout << " Afseal - Generating Keys" << endl;
    he.KeyGen();
	std::cout << " Afseal - Keys Generated" << endl;
    
	vector<long> v1;
    vector<long> v2;
    for(int i=0; i<10; i++){
        if(i<VECTOR_SIZE)   { v1.push_back(i);  }
        else                { v1.push_back(0);  }}
    for(int i=0; i<10; i++){
        if(i<VECTOR_SIZE)   { v2.push_back(2);  }
        else                { v2.push_back(0);  }}
	for (auto i: v1)
	  std::cout << i << ' ';
	for (auto i: v2)
	  std::cout << i << ' ';
    // Sum
    Ciphertext k1 = he.encrypt(v1);
    Ciphertext k2 = he.encrypt(v2);
    he.add(k1, k2);
    vector<long> vRes = he.decrypt(k1);
 	for (auto i: vRes)
	  std::cout << i << ' ';

    // Multiplication
    k1 = he.encrypt(v1);
    k2 = he.encrypt(v2);
    he.multiply(k1, k2);
    vector<long> vRes2 = he.decrypt(k1);
	for (auto i: vRes2)
	  std::cout << i << ' ';
	
    // Scalar product
    k1 = he.encrypt(v1);
    k2 = he.encrypt(v2);
    he.sub(k1, k2);
    vector<long> vRes3 = he.decrypt(k1);
	for (auto i: vRes3)
	  std::cout << i << ' ';
    // Square
    k1 = he.encrypt(v1);
    he.square(k1);
    vector<long> vRes4 = he.decrypt(k1);
	for (auto i: vRes4)
	  std::cout << i << ' ';
    // Store & retrieve environment
    he.saveEnv(fileName);
    std::cout << "Saved env with values: m=" << he.getM() <<
        ", p=" << he.getP() << ", r=" << he.getR() << endl;
    std::cout << "END OF DEMO" << endl;
};

