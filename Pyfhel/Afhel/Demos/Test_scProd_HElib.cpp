#include <cstddef>
#include <sys/time.h>
#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/ZZX.h>
#include <NTL/ZZ.h>

#define VEC_SIZE 4

// Simple class to measure time for each method
class Timer
{
public:
    void start() { m_start = my_clock(); }
    void stop() { m_stop = my_clock(); }
    double elapsed_time() const {
        return m_stop - m_start;
    }

private:
    double m_start, m_stop;
    double my_clock() const {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec + tv.tv_usec * 1e-6;
    }
};

NTL::ZZ noPackingMultiplyAndSum(long u[], long v[], FHESecKey sk, FHEPubKey pk)
{
    // Vectors to hold the ciphertexts created from the elements of u and v
    std::vector<Ctxt> encU;
    std::vector<Ctxt> encV;

    // Each element is encrypted individually
    for (int i = 0; i < VEC_SIZE; i++) {
        Ctxt tempU(pk);
        pk.Encrypt(tempU, to_ZZX(u[i]));
        encU.push_back(tempU);

        Ctxt tempV(pk);
        pk.Encrypt(tempV, to_ZZX(v[i]));
        encV.push_back(tempV);
    }

    // Multiply the corresponding positions of vectors and set the result in encU
    for (int i = 0; i < VEC_SIZE; i++) {
        encU[i] *= encV[i];
    }

    // Sum all the elements in encU and save the result in the first position
    for (int i = 1; i < VEC_SIZE; i++) {
        encU[0] += encU[i];
    }

    // Decrypt the first position of the vector, which holds the value of the scalar product
    ZZX result;
    sk.Decrypt(result, encU[0]);

    return result[0];
}

NTL::ZZ invertAndMultiply(long u[], long v[], FHESecKey sk, FHEPubKey pk)
{
    // ZZX is a class for polynomials from the NTL library
    ZZX U, V;                               

    // Set the length of the polynomial U(x) and V(x)
    U.SetLength(VEC_SIZE);
    V.SetLength(VEC_SIZE);

    // Set the coefficients of the polynomials U(x) and V(x).
    // Note that the elements from v are "inverted" when encoded into the coefficients of V(x)
    for (int i = 0; i < VEC_SIZE; i++) {
        SetCoeff(U, i, u[i]);                   //E.g.: U(x) = 1 + 2x + 3x^2 + 4x^3
        SetCoeff(V, (VEC_SIZE - 1) - i, v[i]);  //E.g.: V(x) = 4 + 3x + 2x^2 + 1x^3
    }

    // Ciphertexts that will hold the polynomials encrypted using public key pk
    Ctxt encU(pk);                          
    Ctxt encV(pk);                          

    // Encrypt the polynomials into the ciphertexts
    pk.Encrypt(encU, U);
    pk.Encrypt(encV, V);    

    // Multiply the ciphertexts and store the result into encU
    encU *= encV;

    // Decrypt the multiplied ciphertext into a polynomial using the secret key sk
    ZZX result;
    sk.Decrypt(result, encU);

    return result[VEC_SIZE - 1]; 
}

NTL::ZZ multiplyAndTotalSum(long u[], long v[], FHEPubKey pk, FHESecKey sk, FHEcontext& context)
{
    // Creates a helper object based on the context
    EncryptedArray ea(context, context.alMod.getFactorsOverZZ()[0]); 

    // Create vectors from the values from the arrays.
    // The vectors should have the same size as the EncryptedArray (ea.size),
    // so fill the other positions with 0 which won't change the result
    std::vector<long int> U(u, u + VEC_SIZE);
    std::vector<long int> V(v, v + VEC_SIZE);
    for (int i = VEC_SIZE; i < ea.size(); i++) {
        U.push_back(0);
        V.push_back(0);
    }

    // Ciphertexts that will hold the encrypted vectors
    Ctxt encU(pk);
    Ctxt encV(pk);

    // Encrypt the whole vector into one ciphertext using packing
    ea.encrypt(encU, pk, U);
    ea.encrypt(encV, pk, V);

    // Multiply ciphertexts and set the result to encU
    encU.multiplyBy(encV);

    // Use the totalSums functions to sum all the elements 
    // The result will have the sum in all positions of the vector
    totalSums(ea, encU);

    // Decrypt the result (i.e., the scalar product value)
    ZZX result;
    sk.Decrypt(result, encU);

    return result[0];
}

int main(int argc, char **argv)
{
    /*** INITIALIZATION ***/
    long m = 0;                   // Specific modulus
    long p = 257;                 // Plaintext base [default=2], should be a prime number
    long r = 3;                   // Lifting [default=1]
    long L = 10;                  // Number of levels in the modulus chain [default=heuristic]
    long c = 2;                   // Number of columns in key-switching matrix [default=2]
    long w = 64;                  // Hamming weight of secret key
    long d = 1;                   // Degree of the field extension [default=1]
    long k = 80;                  // Security parameter [default=80] 
    long s = 0;                   // Minimum number of slots [default=0]

    Timer tInit;
    tInit.start();
    
    std::cout << "Finding m... " << std::flush;
    m = FindM(k, L, c, p, d, s, 0);           // Find a value for m given the specified values
    std::cout << "m = " << m << std::endl;
    
    std::cout << "Initializing context... " << std::flush;
    FHEcontext context(m, p, r);              // Initialize context
    buildModChain(context, L, c);             // Modify the context, adding primes to the modulus chain
    std::cout << "OK!" << std::endl;

    std::cout << "Generating keys... " << std::flush;
    FHESecKey sk(context);                    // Construct a secret key structure
    const FHEPubKey& pk = sk;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
    sk.GenSecKey(w);                          // Actually generate a secret key with Hamming weight
    addSome1DMatrices(sk);                    // Extra information for relinearization
    std::cout << "OK!" << std::endl;

    // Arrays whose elements will be the coefficients of the polynomials U(x) and V(x)
    long u[VEC_SIZE];
    long v[VEC_SIZE];

    // Initialize arrays with sequential numbers, starting from 1
    for (int i = 0; i < VEC_SIZE; i++) {
        u[i] = i+1;
        v[i] = i+1;
    }
    tInit.stop();
    std::cout << "Time taken for the initialization: " << tInit.elapsed_time() << std::endl;
    
    /*** METHOD 1: MULTIPLY AND SUM ARRAYS WITHOUT PACKING ***/
    Timer tMethod1;
    tMethod1.start();
    ZZ method1Result = noPackingMultiplyAndSum(u, v, sk, pk);
    tMethod1.stop();
    std::cout << "Muliply and sum arrays without packing method result: " << method1Result << ". Done in " << tMethod1.elapsed_time() << "s." <<  std::endl;    
    
    /*** METHOD 2: USE COEFFICIENT PACKING, INVERT AND MULTIPLY POLYNOMIALS***/
    Timer tMethod2;
    tMethod2.start();
    ZZ method2Result = invertAndMultiply(u, v, sk, pk);
    tMethod2.stop();
    std::cout << "Invert and multiply method result: " << method2Result << ". Done in " << tMethod2.elapsed_time() << "s." <<  std::endl;   

    /*** METHOD 3: USE SUBFIELDS PACKING, MULTIPLY AND SUM  ***/
    Timer tMethod3;
    tMethod3.start();
    ZZ method3Result = multiplyAndTotalSum(u, v, pk, sk, context);
    tMethod3.stop();
    std::cout << "Multiply and totalSum method result: " << method3Result << ". Done in " << tMethod3.elapsed_time() << "s." <<  std::endl; 
}
