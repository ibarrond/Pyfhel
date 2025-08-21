"""
Integer FHE with BGV scheme
========================================

This demo showcases the use of the BGV scheme for integer FHE operations.
"""


# %%
# 1. BGV context and key setup
# ------------------------------------------------------------------------------
# We take a look at the different parameters that can be set for the BGV scheme.
import numpy as np
from Pyfhel import Pyfhel
HE = Pyfhel()           # Creating empty Pyfhel object

# HE.contextGen(scheme='bgv', n=2**14, t_bits=20)  # Generate context for 'bfv'/'bgv'/'ckks' scheme

bgv_params = {
    'scheme': 'BGV',    # can also be 'bgv'
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
HE.contextGen(**bgv_params)  # Generate context for bgv scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
HE.rotateKeyGen()       # Rotate key generation --> Allows rotation/shifting
HE.relinKeyGen()        # Relinearization key generation

print("\n1. Pyfhel FHE context generation")
print(f"\t{HE}")


# %%
# 2. BGV Integer Encryption
# ---------------------------
# we will define two integers and encrypt them using `encryptBGV`:
integer1 = np.array([127], dtype=np.int64)
integer2 = np.array([-2], dtype=np.int64)
ctxt1 = HE.encryptBGV(integer1) # Encryption makes use of the public key
ctxt2 = HE.encryptBGV(integer2) # For BGV, encryptBGV function is used.
print("\n3. BGV Encryption, ")
print("    int ",integer1,'-> ctxt1 ', type(ctxt1))
print("    int ",integer2,'-> ctxt2 ', type(ctxt2))
# %%
# # The best way to obtain information from a ciphertext is to print it:
print(ctxt1)
print(ctxt2)

# %%
# 3. Operating with encrypted integers in BGV
# ---------------------------------------------
# Relying on the context defined before, we will now operate
# (addition, substaction, multiplication) the two ciphertexts:
ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for inplace operation
ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for inplace operation
ctxtMul = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for inplace operation
print("\n3. Operating with encrypted integers")
print(f"Sum: {ctxtSum}")
print(f"Sub: {ctxtSub}")
print(f"Mult:{ctxtMul}")

# %%
# 4.  Decrypting BGV integers
# ------------------------------
# Once we're finished with the encrypted operations, we can use
# the Pyfhel instance to decrypt the results using `decryptBGV`:
resSum = HE.decryptBGV(ctxtSum) # Decryption must use the corresponding function
                                #  decryptBGV.
resSub = HE.decrypt(ctxtSub)    # `decrypt` function detects the scheme and
                                #  calls the corresponding decryption function.
resMul = HE.decryptBGV(ctxtMul)
print("\n4. Decrypting BGV result:")
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)


# %%
# 5. BGV Integer Array Encoding & Encryption
# ------------------------------------------------------------------------------
# we will define two 1D integer arrays, encode and encrypt them:
# arr1 = [0, 1, ... n-1] (length n)
# arr2 = [-t//2, -1, 1]  (length 3) --> Encoding fills the rest of the array with zeros

arr1 = np.arange(bgv_params['n'], dtype=np.int64)    # Max possible value is t/2-1. Always use type int64!
arr2 = np.array([-bgv_params['t']//2, -1, 1], dtype=np.int64)  # Min possible value is -t/2.

ptxt1 = HE.encodeBGV(arr1)   # Creates a PyPtxt plaintext with the encoded arr1
                             # plaintexts created from arrays shorter than 'n' are filled with zeros.
ptxt2 = HE.encode(arr2)      # `encode` function detects the scheme and calls the
                             #  corresponding encoding function.

assert np.allclose(HE.decodeBGV(ptxt1), arr1)  # Decoding the encoded array should return the original array
assert np.allclose(HE.decode(ptxt2)[:3], arr2)     # `decode` function detects the scheme

ctxt1 = HE.encryptPtxt(ptxt1) # Encrypts the plaintext ptxt1 and returns a PyCtxt
ctxt2 = HE.encryptPtxt(ptxt2) #  Alternatively you can use HE.encryptInt(arr2)

# Otherwise, a single call to `HE.encrypt` would detect the data type,
#  encode it and encrypt it
#> ctxt1 = HE.encrypt(arr1)

print("\n6. Integer Array Encoding & Encryption, ")
print("->\tarr1 ", arr1,'\n\t==> ptxt1 ', ptxt1,'\n\t==> ctxt1 ', ctxt1)
print("->\tarr2 ", arr2,'\n\t==> ptxt2 ', ptxt2,'\n\t==> ctxt2 ', ctxt2)

# %%
# 6. BGV Integer Array Encoding & Encryption
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

# Ciphetext-plaintext ops
cpSum = ctxt1 + ptxt2       # Calls HE.add_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 += ctxt2` for inplace operation
cpSub = ctxt1 - ptxt2       # Calls HE.sub_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 -= ctxt2` for inplace operation
cpMul = ctxt1 * ptxt2       # Calls HE.multiply_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 *= ctxt2` for inplace operation


print("\n6. Secure BGV operations")
print(" Ciphertext-ciphertext: ")
print("->\tctxt1 + ctxt2 = ccSum: ", ccSum)
print("->\tctxt1 - ctxt2 = ccSub: ", ccSub)
print("->\tctxt1 * ctxt2 = ccMul: ", ccMul)
print(" Single ciphertext: ")
print("->\tctxt1**2      = cSq  : ", cSq  )
print("->\t- ctxt1       = cNeg : ", cNeg )
print("->\tctxt1**3      = cPow : ", cPow )
print("->\tctxt1 >> 2    = cRotR: ", cRotR)
print("->\tctxt1 << 2    = cRotL: ", cRotL)
print(" Ciphertext-plaintext: ")
print("->\tctxt1 + ptxt2 = cpSum: ", cpSum)
print("->\tctxt1 - ptxt2 = cpSub: ", cpSub)
print("->\tctxt1 * ptxt2 = cpMul: ", cpMul)


# %%
# 7. BGV Relinearization: What, why, when
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

print("\n7. Relinearization-> Right after each multiplication.")
print(f"ccMul before relinearization (size {ccMul.size()}): {ccMul}")
~ccMul    # Equivalent to HE.relinearize(ccMul). Relin always happens in-place.
print(f"ccMul after relinearization (size {ccMul.size()}): {ccMul}")
print(f"cPow after 2 mult&relin rounds:  (size {cPow.size()}): {cPow}")

# %%
# 8. Decrypt & Decode results
# ------------------------------------------------------------------------------
# Time to decrypt results! We use HE.decryptBGV for this.
#  HE.decrypt() could also be used, in which case the decryption type would be
#  inferred from the ciphertext metadata.
r1     = HE.decryptBGV(ctxt1)
r2     = HE.decryptBGV(ctxt2)
rccSum = HE.decryptBGV(ccSum)
rccSub = HE.decryptBGV(ccSub)
rccMul = HE.decryptBGV(ccMul)
rcSq   = HE.decryptBGV(cSq  )
rcNeg  = HE.decryptBGV(cNeg )
rcPow  = HE.decryptBGV(cPow )
rcRotR = HE.decryptBGV(cRotR)
rcRotL = HE.decryptBGV(cRotL)
rcpSum = HE.decryptBGV(cpSum)
rcpSub = HE.decryptBGV(cpSub)
rcpMul = HE.decryptBGV(cpMul)

print("\n8. Decrypting results")
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
print(" Ciphertext-plaintext ops: ")
print("   ->\tctxt1 + ptxt2 = cpSum --(decr)--> ", rcpSum)
print("   ->\tctxt1 - ptxt2 = cpSub --(decr)--> ", rcpSub)
print("   ->\tctxt1 * ptxt2 = cpMul --(decr)--> ", rcpMul)


# sphinx_gallery_thumbnail_path = 'static/thumbnails/encoding.png'
# %%