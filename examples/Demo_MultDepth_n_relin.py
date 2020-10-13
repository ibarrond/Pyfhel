# Fractional / float Demo for Pyfhel, covering the different ways of encrypting
#   and decrypting.

from Pyfhel import Pyfhel, PyPtxt, PyCtxt

print("==============================================================")
print("============ Pyfhel MultDepth and Relineraization ============")
print("==============================================================")
print(" This demo focuses on ciphertext size and noise budget")

print("1. Creating Context and KeyGen in a Pyfhel Object. Using 64 ")
print("     bits for integer part and 32 bits for decimal part.")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537, base=2, intDigits=64, fracDigits = 32) 
                        # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters.py, and
                        #  in the docs of the function (link to docs in README)
HE.keyGen()             # Key Generation.
print(HE)

print("2. Encrypting Fractionals")
float1 = -2.3
float2 = 3.4
ctxt1 = HE.encryptFrac(float1) # Encryption makes use of the public key
ctxt2 = HE.encryptFrac(float2) # For integers, encryptInt function is used.
print("    int ",float1,'-> ctxt1 ', type(ctxt1))
print("    int ",float2,'-> ctxt2 ', type(ctxt2))
print(ctxt1)
print(ctxt2)


print("3. Operating with encrypted fractionals multiple times")
print("     ctxtMul1 = ctxt1 * ctxt2")
ctxtMul1 = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation
print(ctxtMul1)
print("   Notice the increase in size: size(ctxtMul1) = size(ctxt1) + size(ctxt2) - 1")
print("   This rule applies for all multiplications.")
print("   This size increase makes further operations slower, and requires more memory")


print("4. Relinearization reduces the size of a ciphertext back to 2, thus it is very convenient for deep multiplications")
print("    First we generate relinearization keys.")
print("    Make sure the bitcount is higher than the size of your ciphertexts")
HE.relinKeyGen(1, 1)

ctxtMul1 = ~ ctxtMul1 # Equivalent to HE.relinearize(ctxtMul)
                      # and equivalent to  ~ctxtMul1 (without assignment)
print(ctxtMul1)
print("   Good! size increase is solved with relinearization.")


print("5. Noise budget: You can see ciphertexts as noisy signals. Every multiplication will drastically increase the noise, thus reducing the noise budget.")
print("   Notice the decrease in noise budget in the previous multiplication")
print("   If the noise budget reaches zero, we won't be able to decrypt correctly!")
print("ctxtMulsq = ctxtMult1**2")
ctxtMulsq = ctxtMul1**2
print(ctxtMulsq)
print("     decrypt(ctxtMul1) =  ", HE.decryptFrac(ctxtMul1))
print(f"      expected: {float1*float2}")
print("     decrypt(ctxtMulsq) =  ", HE.decryptFrac(ctxtMulsq))
print(f"      expected: {(float1*float2)**2}")

print("6. I need more noise budget! You have several options:")
print("  - Use better context parameters (mainly increase m, reduce p, reduce intDigits and fracDigits")
print("    -> Try this demo changing p to be 63 (enough to hold the result value) -> precision lowers, but operations are faster and noise budget decreases slower")
print("    -> Try this demo with m=8192 (more multiplications are allowed, but operations are slower")
print("  - Decrypt and encrypt again.")
print("  - Use bootstrapping: Sadly it is not available in SEAL, and even if it were, it would be extremely inefficient. It is always better to resort to the first option")
HE
