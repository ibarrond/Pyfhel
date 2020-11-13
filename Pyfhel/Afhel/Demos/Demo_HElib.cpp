#include <fhe/FHE.h>
#include <fhe/EncryptedArray.h>
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>

using namespace std;

int main(int argc, char **argv)
{
    /* 
     *  TITLE: DEMO OF HELIB USAGE
        Description: This is a DEMO created for the PrivacyForBigData project in EURECOM.
        Authors: Luca BENEDETTO, Alberto IBARRONDO
        Date: 04/05/2017
        License: 
    */
    
    cout << "> DEMO OF HELIB USAGE, PrivacyForBigData project in EURECOM" << endl;

    // ----------------- SET UP CONTEXT -------------------
    // Transformation parameters
    long L=16;      // L - Levels, # of primes in modulus chain. HEURISTIC
    long c=3;       // c - Columns in key switching matrix
    long d=0;		// d - degree of the field extension
	        		//      * (d == 0 => factors[0] defined the extension) 	
    // Security parameters
    long k=128;	    // k - security parameter, in bits
    long w=64;      // w - Hamming weight of secret key
    
    // Plaintext space parameters
    long r=54;		// r - lifting in the space
    long p=2;       // p - plaintext base -> 2 is binary {0,1}; 257 is a byte
                    // 	* Computations will be 'modulo p'. It MUST be prime
    long m=0;		// m - specific modulus, to be calculated below using FindM
    long s=0;       // s - minimum number of slots
    m = FindM(k,L,c,p, d, 0, 0);

    FHEcontext context(m, p, r);        // Initialize context
    buildModChain(context, L, c);       // Modify context, adding primes to modulus chain
    ZZX G = context.alMod.getFactorsOverZZ()[0]; // Creates polynomial used to encrypt
    EncryptedArray ea(context, G);


    cout << "    1. SET UP CONTEXT -> context"<<endl;
    cout << "      L = "<<L<<" (Levels, # of primes in modulus chain)"<<endl;
    cout << "      c = "<<c<<" (Columns in key switching matrix)"<<endl;
    cout << "      d = "<<d<<" (Degree of field extention)"<<endl;
    cout << "      s = "<<s<<" (Bits of security)"<<endl;
    cout << "      w = "<<w<<" (Hamming weight of secret key)"<<endl;
    cout << "      r = "<<r<<" (Lifting in the space)"<<endl;
    cout << "      p = "<<p<<" (Plaintext Base)"<<endl;
    cout << "      m = "<<m<<" (Specific modulus calculated with FindM)"<<endl;


    // ----------------- KEY GENERATION -------------------
    
    // Construct a secret key structure
    FHESecKey secretKey(context);  
    const FHEPubKey& publicKey = secretKey; // "upcast": FHESecKey = subclass of FHEPubKey
	                		       // NOTE: public key was extracted from secret key	
    secretKey.GenSecKey(w);  	   // Generates a secret key with Hamming weight w

    cout << "    2. KEY GENERATION"<<endl;
    cout << "      Generated Secret Key from context -> secretKey" << endl;
    cout << "      Generated public key from secret key -> publicKey" << endl;   
    


    // ------------------- ENCRYPTION ---------------------
    cout << "    3. ENCRYPTION USING PUBLIC KEY"<<endl;

    //   ......... Defining plaintexts .........
    long plaintext1 = 5;           // First plaintext
    long plaintext2 = 100;         // Second plaintext
    cout << "      Defined The Two plaintexts (type long): 5, 100"<<endl;

    //   ......... Defining Cyphertexts.........
    Ctxt ct1(publicKey);           // Cyphertext 1 object
    Ctxt ct2(publicKey);           // Cyphertext 2 object
    cout << "      Defined The Cyphertexts -> ct1, ct2"<<endl;

    //   ..... Encrypting with public key ......
    publicKey.Encrypt(ct1,to_ZZX(plaintext1)); // Use encrypt from encrypted array
    publicKey.Encrypt(ct2,to_ZZX(plaintext2)); // Use encrypt from encrypted array
    cout << "      Encrypted both with public key from key generation -> (ct1, ct2)"<<endl;



    // ------------- HOMOMORPHIC OPERATIONS ---------------
    Ctxt ctSum = ct1;              // Cyphertext for sum operation on this demo
    Ctxt ctProd = ct1;             // Cyphertext for product operation on this demo

    ctSum += ct2;
    ctProd *= ct2; 

    cout << "    4. HOMOMORPHIC OPERATIONS"<<endl;
    cout << "      Computed the sum and the product of ct1 and ct2 -> ctSum, ctProd"<<endl;

    // ------------------ DECRYPTION ----------------------
    ZZX res;
    cout << "    5. DECRYPTION USING SECRET KEY"<<endl;
    
    // Result of sum   
    secretKey.Decrypt(res, ctSum);  // Decrypt the sum using the private key
    cout << "     Sum:"<<endl;   
    cout << "       " << plaintext1 << " + " << plaintext2 << " = " << res[0] << endl;

    // Result of multiplication
    secretKey.Decrypt(res, ctProd); // Decrypt the product
    cout << "     Product:"<<endl;
    cout << "       " << plaintext1 << " + " << plaintext2 << " = " << res[0] << endl;


    return 0;   // END OF DEMO
}
