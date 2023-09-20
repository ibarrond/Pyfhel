"""
Integer FHE with BFV scheme
========================================

Integer FHE Demo for Pyfhel, covering all the posibilities offered by Pyfhel
regarding the BFV scheme (see https://eprint.iacr.org/2012/144.pdf).
"""

import numpy as np
from Pyfhel import Pyfhel

# %%
# 1. BFV context and key setup
# ------------------------------------------------------------------------------
# We take a look at the different parameters that can be set for the BFV scheme.
# Ideally, one should use as little `n` and `t` as possible while keeping the
# correctness in the operations.
# The noise budget in a freshly encrypted ciphertext is
#
#     ~ log2(coeff_modulus/plain_modulus) (bits)
#
# By far the most demanding operation is the homomorphic (ciphertext-ciphertext)
# multiplication, consuming a noise budget of around:
#
#     log2(plain_modulus) + (other terms).

HE = Pyfhel()           # Creating empty Pyfhel object
bfv_params = {
    'scheme': 'BFV',    # can also be 'bfv'
    'n': 2**13,         # Polynomial modulus degree, the num. of slots per plaintext,
                        #  of elements to be encoded in a single ciphertext in a
                        #  2 by n/2 rectangular matrix (mind this shape for rotations!)
                        #  Typ. 2^D for D in [10, 16]
    't': 65537,         # Plaintext modulus. Encrypted operations happen modulo t
                        #  Must be prime such that t-1 be divisible by 2^N.
    't_bits': 20,       # Number of bits in t. Used to generate a suitable value 
                        #  for t. Overrides t if specified.
    'sec': 128,         # Security parameter. The equivalent length of AES key in bits.
                        #  Sets the ciphertext modulus q, can be one of {128, 192, 256}
                        #  More means more security but also slower computation.
}
HE.contextGen(**bfv_params)  # Generate context for bfv scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
HE.rotateKeyGen()       # Rotate key generation --> Allows rotation/shifting
HE.relinKeyGen()        # Relinearization key generation

print("\n1. Pyfhel FHE context generation")
print(f"\t{HE}")

# %%
# 2. Integer Array Encoding & Encryption
# ------------------------------------------------------------------------------
# we will define two 1D integer arrays, encode and encrypt them:
# arr1 = [0, 1, ... n-1] (length n)
# arr2 = [-t//2, -1, 1]  (length 3) --> Encoding fills the rest of the array with zeros

arr1 = np.arange(bfv_params['n'], dtype=np.int64)    # Max possible value is t/2-1. Always use type int64!
arr2 = np.array([-bfv_params['t']//2, -1, 1], dtype=np.int64)  # Min possible value is -t/2. 

ptxt1 = HE.encodeInt(arr1)   # Creates a PyPtxt plaintext with the encoded arr1
ptxt2 = HE.encodeInt(arr2)   # plaintexts created from arrays shorter than 'n' are filled with zeros.

ctxt1 = HE.encryptPtxt(ptxt1) # Encrypts the plaintext ptxt1 and returns a PyCtxt
ctxt2 = HE.encryptPtxt(ptxt2) #  Alternatively you can use HE.encryptInt(arr2)

# Otherwise, a single call to `HE.encrypt` would detect the data type,
#  encode it and encrypt it
#> ctxt1 = HE.encrypt(arr1)

print("\n2. Integer Encoding & Encryption, ")
print("->\tarr1 ", arr1,'\n\t==> ptxt1 ', ptxt1,'\n\t==> ctxt1 ', ctxt1)
print("->\tarr2 ", arr2,'\n\t==> ptxt2 ', ptxt2,'\n\t==> ctxt2 ', ctxt2)

# %%
# 3. Securely operating on encrypted ingeger arrays
# ------------------------------------------------------------------------------
# We try all the operations supported by Pyfhel.
#  Note that, to operate, the ciphertexts/plaintexts must be built with the same
#  context. Internal checks prevent ops between ciphertexts of different contexts.

# Ciphertext-ciphertext ops:
ccSum = ctxt1 + ctxt2       # Calls HE.add(ctxt1, ctxt2, in_new_ctxt=True)
                            #  `ctxt1 += ctxt2` for inplace operation
ccSub = ctxt1 - ctxt2       # Calls HE.sub(ctxt1, ctxt2, in_new_ctxt=True)
                            #  `ctxt1 -= ctxt2` for inplace operation
ccMul = ctxt1 * ctxt2       # Calls HE.multiply(ctxt1, ctxt2, in_new_ctxt=True)
                            #  `ctxt1 *= ctxt2` for inplace operation
cSq   = ctxt1**2            # Calls HE.square(ctxt1, in_new_ctxt=True)
                            #  `ctxt1 **= 2` for inplace operation
cNeg  = -ctxt1              # Calls HE.negate(ctxt1, in_new_ctxt=True)
                            # 
cPow  = ctxt1**3            # Calls HE.power(ctxt1, 3, in_new_ctxt=True)
                            #  `ctxt1 **= 3` for inplace operation
cRotR = ctxt1 >> 2          # Calls HE.rotate(ctxt1, k=2, in_new_ctxt=True)
                            #  `ctxt1 >>= 2` for inplace operation
                            # WARNING! the encoded data is placed in a n//2 by 2
                            #  matrix. Hence, these rotations apply independently
                            #  to each of the rows!
cRotL = ctxt1 << 2          # Calls HE.rotate(ctxt1, k=-2, in_new_ctxt=True)
                            #  `ctxt1 <<= 2` for inplace operation
cFlip = ctxt1 ^ 1           # Calls HE.flip(ctxt1, k=1, in_new_ctxt=True)
                            #  `ctxt1 |= 1` for inplace operation
cCuAdd = (+ctxt1)           # Calls HE.cumul_add(ctxt1, in_new_ctxt=True)
                            #  There is no equivalent for in-place operator, use
                            #  the above call with `in_new_ctxt=False` if required.

# Ciphetext-plaintext ops
cpSum = ctxt1 + ptxt2       # Calls HE.add_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 += ctxt2` for inplace operation
cpSub = ctxt1 - ptxt2       # Calls HE.sub_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 -= ctxt2` for inplace operation
cpMul = ctxt1 * ptxt2       # Calls HE.multiply_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 *= ctxt2` for inplace operation


print("3. Secure operations")
print(" Ciphertext-ciphertext: ")
print("->\tctxt1 + ctxt2 = ccSum: ",  ccSum)
print("->\tctxt1 - ctxt2 = ccSub: ",  ccSub)
print("->\tctxt1 * ctxt2 = ccMul: ",  ccMul)
print(" Single ciphertext: ")
print("->\tctxt1**2      = cSq  : ",  cSq  )
print("->\t- ctxt1       = cNeg : ",  cNeg )
print("->\tctxt1**3      = cPow : ",  cPow )
print("->\tctxt1 >> 2    = cRotR: ",  cRotR)
print("->\tctxt1 << 2    = cRotL: ",  cRotL)
print("->\tctxt1 | 1     = cFlip: ",  cFlip)
print("->\t(+ctxt1)      = cCuAdd: ", cCuAdd)
print(" Ciphertext-plaintext: ")
print("->\tctxt1 + ptxt2 = cpSum: ",  cpSum)
print("->\tctxt1 - ptxt2 = cpSub: ",  cpSub)
print("->\tctxt1 * ptxt2 = cpMul: ",  cpMul)

          
# %%
# 4. BFV Relinearization: What, why, when
# ------------------------------------------------------------------------------
# Ciphertext-ciphertext multiplications increase the size of the polynoms 
#  representing the resulting ciphertext. To prevent this growth, the 
#  relinearization technique is used (typically right after each c-c mult) to 
#  reduce the size of a ciphertext back to the minimal size (two polynoms c0 & c1).
#  For this, a special type of public key called Relinearization Key is used.
#
# In Pyfhel, you can either generate a relin key with HE.RelinKeyGen() or skip it
#  and call HE.relinearize() directly, in which case a warning is issued.
# 
# Note that HE.power performs relinearization after every multiplication.

print("\n4. Relinearization-> Right after each multiplication.")
print(f"ccMul before relinearization (size {ccMul.size()}): {ccMul}")
~ccMul    # Equivalent to HE.relinearize(ccMul). Relin always happens in-place.
print(f"ccMul after relinearization (size {ccMul.size()}): {ccMul}")
print(f"cPow after 2 mult&relin rounds:  (size {cPow.size()}): {cPow}")

# %%
# 5. Decrypt & Decode results
# ------------------------------------------------------------------------------
# Time to decrypt results! We use HE.decryptInt for this. 
#  HE.decrypt() could also be used, in which case the decryption type would be
#  inferred from the ciphertext metadata. 
r1     = HE.decryptInt(ctxt1)
r2     = HE.decryptInt(ctxt2)
rccSum = HE.decryptInt(ccSum)
rccSub = HE.decryptInt(ccSub)
rccMul = HE.decryptInt(ccMul)
rcSq   = HE.decryptInt(cSq  )
rcNeg  = HE.decryptInt(cNeg )
rcPow  = HE.decryptInt(cPow )
rcRotR = HE.decryptInt(cRotR)
rcRotL = HE.decryptInt(cRotL)
rcFlip = HE.decryptInt(cFlip)
rcCuAdd = HE.decryptInt(cCuAdd)
rcpSum = HE.decryptInt(cpSum)
rcpSub = HE.decryptInt(cpSub)
rcpMul = HE.decryptInt(cpMul)

print("5. Decrypting results")
print(" Original ciphertexts: ")
print("   ->\tctxt1 --(decr)--> ", r1)
print("   ->\tctxt2 --(decr)--> ", r2)
print(" Ciphertext-ciphertext Ops: ")
print("   ->\tctxt1 + ctxt2 = ccSum --(decr)--> ", rccSum)
print("   ->\tctxt1 - ctxt2 = ccSub --(decr)--> ", rccSub)
print("   ->\tctxt1 * ctxt2 = ccMul --(decr)--> ", rccMul)
print(" Single ciphertext: ")
print("   ->\tctxt1**2      = cSq   --(decr)--> ", rcSq  )
print("   ->\t- ctxt1       = cNeg  --(decr)--> ", rcNeg )
print("   ->\tctxt1**3      = cPow  --(decr)--> ", rcPow )
print("   ->\tctxt1 >> 2    = cRotR --(decr)--> ", rcRotR)
print("   ->\tctxt1 << 2    = cRotL --(decr)--> ", rcRotL)
print("   ->\tctxt1 | 1     = cFlip --(decr)--> ", rcFlip)
print("   ->\t(+tctxt1)     = cCuAdd -(decr)--> ", rcCuAdd)
print(" Ciphertext-plaintext ops: ")
print("   ->\tctxt1 + ptxt2 = cpSum --(decr)--> ", rcpSum)
print("   ->\tctxt1 - ptxt2 = cpSub --(decr)--> ", rcpSub)
print("   ->\tctxt1 * ptxt2 = cpMul --(decr)--> ", rcpMul)


# sphinx_gallery_thumbnail_path = 'static/thumbnails/encoding.png'
# %%
