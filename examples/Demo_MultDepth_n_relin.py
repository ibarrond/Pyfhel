"""
MultDepth and Relineraization
==============================

This demo focuses on managing ciphertext size and noise budget.

Each ciphertext can be seen as (oversimplifying a bit) a polynomial with noise.
When you perform encrypted multiplication, the size of the output polynomial grows
based on the size of the tho muliplicands, which increases its memory footprint
and slows down operations. In order to keep ciphertext sizes low (min. 2), it
is recommended to relinearize after each multiplication, effectively shrinking
the ciphertext back to minimum size. This demo will show relinearization in action.

Besides all this, the noise inside the ciphertext grows greatly when multiplying.
Each ciphertext is given a noise budget when first encrypted, which decreases
irreversibly for each multiplication. If the noise budget reaches zero, the
resultin ciphertext cannot be decrypted correctly anymore. This demo will present
several strategies to deal with high noise.
"""
# sphinx_gallery_thumbnail_path = 'static/thumbnails/multDepth.jpg'


# %%
# We start by importing the library with the three main classes:
# 
# * Pyfhel class contains most of the functions.
# * PyPtxt is the plaintext class
from Pyfhel import Pyfhel, PyPtxt, PyCtxt


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
print("    * Make sure the relinKey size is higher than the size of the ciphertext you want to relinearize.")
print("    * bigger bitCount means faster relinarization, but also bigger decrease in noiseBudget. Needs to be within [1, 60]")
relinKeySize=5
HE.relinKeyGen(bitCount=1, size=relinKeySize)
print("   We can now relinearize!")
assert relinKeySize >= ctxtMul1.size()

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
print("    -> Try this demo with m=8192 (more multiplications are allowed, but operations are slower)")
print("  - Decrypt and encrypt again.")
print("  - Use bootstrapping: Sadly it is not available in SEAL, and even if it were, it would be extremely inefficient. It is always better to resort to the first option")


print("7. How to check the multiplicative depth of a setup? Use the function MultDepth!")
HE.multDepth(max_depth=64, delta=0.1, x_y_z=(1, 10, 0.1), verbose=True)

