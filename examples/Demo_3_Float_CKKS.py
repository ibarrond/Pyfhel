"""
Fixed-point FHE with CKKS scheme
========================================

Fixed-point Demo for Pyfhel, operating with fixed point encoded values following
the CKKS scheme (https://eprint.iacr.org/2016/421.pdf)
"""

# %%
# 1. CKKS context and key setup
# -------------------------------
# We take a look at the different parameters that can be set for the CKKS scheme.
# A generally good strategy to choose `qi_sizes` (bitsize for each prime moduli) 
# for the CKKS scheme is as follows:
#
# 1. Choose a 60-bit prime as the first prime in coeff_modulus. This will
#    give the highest precision when decrypting;
# 2. Choose another 60-bit prime as the last element of coeff_modulus, as
#    this will be used as the special prime and should be as large as the
#    largest of the other primes;
# 3. Choose the intermediate primes to be close to each other.
#
import numpy as np
from Pyfhel import Pyfhel

HE = Pyfhel()           # Creating empty Pyfhel object
ckks_params = {
    'scheme': 'CKKS',   # can also be 'ckks'
    'n': 2**14,         # Polynomial modulus degree. For CKKS, n/2 values can be
                        #  encoded in a single ciphertext. 
                        #  Typ. 2^D for D in [10, 15]
    'scale': 2**30,     # All the encodings will use it for float->fixed point
                        #  conversion: x_fix = round(x_float * scale)
                        #  You can use this as default scale or use a different
                        #  scale on each operation (set in HE.encryptFrac)
    'qi_sizes': [60, 30, 30, 30, 60] # Number of bits of each prime in the chain. 
                        # Intermediate values should be  close to log2(scale)
                        # for each operation, to have small rounding errors.
}
HE.contextGen(**ckks_params)  # Generate context for ckks scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
HE.rotateKeyGen()

# %%
# 2. Float Array Encoding & Encryption
# ----------------------------------------
# we will define two floating-point arrays, encode and encrypt them:
# arr_x = [0.1, 0.2, -0.3] (length 3)
# arr_y = [-1.5, 2.3, 4.7] (length 3)

arr_x = np.array([0.1, 0.2, -0.3], dtype=np.float64)    # Always use type float64!
arr_y = np.array([-1.5, 2.3, 4.7], dtype=np.float64)

ptxt_x = HE.encodeFrac(arr_x)   # Creates a PyPtxt plaintext with the encoded arr_x
ptxt_y = HE.encodeFrac(arr_y)   # plaintexts created from arrays shorter than 'n' are filled with zeros.

ctxt_x = HE.encryptPtxt(ptxt_x) # Encrypts the plaintext ptxt_x and returns a PyCtxt
ctxt_y = HE.encryptPtxt(ptxt_y) #  Alternatively you can use HE.encryptFrac(arr_y)

# Otherwise, a single call to `HE.encrypt` would detect the data type,
#  encode it and encrypt it
#> ctxt_x = HE.encrypt(arr_x)

print("\n2. Fixed-point Encoding & Encryption, ")
print("->\tarr_x ", arr_x,'\n\t==> ptxt_x ', ptxt_x,'\n\t==> ctxt_x ', ctxt_x)
print("->\tarr_y ", arr_y,'\n\t==> ptxt_y ', ptxt_y,'\n\t==> ctxt_y ', ctxt_y)

# %%
# 3. Securely operating on encrypted fixed-point arrays
# -------------------------------------------------------
# We try all the operations supported by Pyfhel.
# Note that, to operate, the ciphertexts/plaintexts must be built with the same
# context. Internal checks prevent ops between ciphertexts of different contexts.

# Ciphertext-ciphertext ops:
ccSum = ctxt_x + ctxt_y       # Calls HE.add(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x += ctxt_y` for inplace operation
ccSub = ctxt_x - ctxt_y       # Calls HE.sub(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x -= ctxt_y` for inplace operation
ccMul = ctxt_x * ctxt_y       # Calls HE.multiply(ctxt_x, ctxt_y, in_new_ctxt=True)
                            #  `ctxt_x *= ctxt_y` for inplace operation
cSq   = ctxt_x**2            # Calls HE.square(ctxt_x, in_new_ctxt=True)
                            #  `ctxt_x **= 2` for inplace operation
cNeg  = -ctxt_x              # Calls HE.negate(ctxt_x, in_new_ctxt=True)
                            # 
# cPow  = ctxt_x**3          # pow Not supported in CKKS
cRotR = ctxt_x >> 2          # Calls HE.rotate(ctxt_x, k=2, in_new_ctxt=True)
                            #  `ctxt_x >>= 2` for inplace operation
cRotL = ctxt_x << 2          # Calls HE.rotate(ctxt_x, k=-2, in_new_ctxt=True)
                            #  `ctxt_x <<= 2` for inplace operation

# Ciphetext-plaintext ops
cpSum = ctxt_x + ptxt_y       # Calls HE.add_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x += ctxt_y` for inplace operation
cpSub = ctxt_x - ptxt_y       # Calls HE.sub_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x -= ctxt_y` for inplace operation
cpMul = ctxt_x * ptxt_y       # Calls HE.multiply_plain(ctxt_x, ptxt_y, in_new_ctxt=True)
                            # `ctxt_x *= ctxt_y` for inplace operation


print("3. Secure operations")
print(" Ciphertext-ciphertext: ")
print("->\tctxt_x + ctxt_y = ccSum: ", ccSum)
print("->\tctxt_x - ctxt_y = ccSub: ", ccSub)
print("->\tctxt_x * ctxt_y = ccMul: ", ccMul)
print(" Single ciphertext: ")
print("->\tctxt_x**2      = cSq  : ", cSq  )
print("->\t- ctxt_x       = cNeg : ", cNeg )
print("->\tctxt_x >> 4    = cRotR: ", cRotR)
print("->\tctxt_x << 4    = cRotL: ", cRotL)
print(" Ciphertext-plaintext: ")
print("->\tctxt_x + ptxt_y = cpSum: ", cpSum)
print("->\tctxt_x - ptxt_y = cpSub: ", cpSub)
print("->\tctxt_x * ptxt_y = cpMul: ", cpMul)

          
# %%
# 4. CKKS relinearization: What, why, when
# -----------------------------------------
# Ciphertext-ciphertext multiplications increase the size of the polynoms 
# representing the resulting ciphertext. To prevent this growth, the 
# relinearization technique is used (typically right after each c-c mult) to 
# reduce the size of a ciphertext back to the minimal size (two polynoms c0 & c1).
# For this, a special type of public key called Relinearization Key is used.
#
# In Pyfhel, you can either generate a relin key with HE.RelinKeyGen() or skip it
# and call HE.relinearize() directly, in which case a warning is issued.

print("\n4. Relinearization-> Right after each multiplication.")
print(f"ccMul before relinearization (size {ccMul.size()}): {ccMul}")
HE.relinKeyGen()
~ccMul    # Equivalent to HE.relinearize(ccMul). Relin always happens in-place.
print(f"ccMul after relinearization (size {ccMul.size()}): {ccMul}")

# %%
# 5. Rescaling & Mod Switching
# -------------------------------
# More complex operations with CKKS require keeping track of the CKKS scale. 
# Operating with two CKKS ciphertexts (or a ciphertext and a plaintext) requires
# them to have the same scale and the same modulus level. 
# 
# -> Scale: Multiplications yield a new scale, which is the product of the scales
#  of the two operands. To scale down a ciphertext, the HE.rescale_to_next(ctxt)
#  function is used, which switches the modulus to the next one in the qi chain
#  and divides the ciphertext by the previous modulus.#  Since this is the only
#  scale-down operation, it is advised to use `scale_bits` with the same size as 
#  the intermediate moduli sizes in HE.qi_sizes. 
# -> Mod Switching: Switches to the next modulus in the qi chain, but without
#  rescaling. This is achieved by the HE.mod_switch_to_next(ctxt) function.
#
# To ease the life of the user, Pyfhel provides `HE.align_mod_n_scale(this, other)`,
# which automatically does the rescaling and mod switching. All the 2-input
# overloaded operators (+, -, \*, /) of PyCtxt automatically call this function.
# The respective HE.add, HE.sub, HE.multiply don't.
#
# NOTE: For more information, check the SEAL example #4_ccks_basics.cpp
# 
# In this example we will compute the mean squared error, treating the average of
# the two ciphertexts as the true distribution. We check the scale and mod-level
# step by step:

#  1. Mean
c_mean = (ctxt_x + ctxt_y) / 2
#  2. MSE
c_mse_1 = ~((ctxt_x - c_mean)**2)
c_mse_2 = (~(ctxt_y - c_mean)**2)
c_mse = (c_mse_1 + c_mse_2)/ 3
#  3. Cumulative sum
c_mse += (c_mse << 1)
c_mse += (c_mse << 2)  # element 0 contains the result
print("\n5. Rescaling & Mod Switching.")
print("->\tMean: ", c_mean)
print("->\tMSE_1: ", c_mse_1)
print("->\tMSE_2: ", c_mse_2)
print("->\tMSE: ", c_mse)



# %%
# 6. Decrypt & Decode results
# ------------------------------
# Time to decrypt results! We use HE.decryptFrac for this. 
#  HE.decrypt() could also be used, in which case the decryption type would be
#  inferred from the ciphertext metadata. 
r_x    = HE.decryptFrac(ctxt_x)
r_y    = HE.decryptFrac(ctxt_y)
rccSum = HE.decryptFrac(ccSum)
rccSub = HE.decryptFrac(ccSub)
rccMul = HE.decryptFrac(ccMul)
rcSq   = HE.decryptFrac(cSq  )
rcNeg  = HE.decryptFrac(cNeg )
rcRotR = HE.decryptFrac(cRotR)
rcRotL = HE.decryptFrac(cRotL)
rcpSum = HE.decryptFrac(cpSum)
rcpSub = HE.decryptFrac(cpSub)
rcpMul = HE.decryptFrac(cpMul)
rmean  = HE.decryptFrac(c_mean)
rmse   = HE.decryptFrac(c_mse)

# Note: results are approximate! if you increase the decimals, you will notice
#  the errors
_r = lambda x: np.round(x, decimals=3)
print("6. Decrypting results")
print(" Original ciphertexts: ")
print("   ->\tctxt_x --(decr)--> ", _r(r_x))
print("   ->\tctxt_y --(decr)--> ", _r(r_y))
print(" Ciphertext-ciphertext Ops: ")
print("   ->\tctxt_x + ctxt_y = ccSum --(decr)--> ", _r(rccSum))
print("   ->\tctxt_x - ctxt_y = ccSub --(decr)--> ", _r(rccSub))
print("   ->\tctxt_x * ctxt_y = ccMul --(decr)--> ", _r(rccMul))
print(" Single ciphertext: ")
print("   ->\tctxt_x**2      = cSq   --(decr)--> ", _r(rcSq  ))
print("   ->\t- ctxt_x       = cNeg  --(decr)--> ", _r(rcNeg ))
print("   ->\tctxt_x >> 4    = cRotR --(decr)--> ", _r(rcRotR))
print("   ->\tctxt_x << 4    = cRotL --(decr)--> ", _r(rcRotL))
print(" Ciphertext-plaintext ops: ")
print("   ->\tctxt_x + ptxt_y = cpSum --(decr)--> ", _r(rcpSum))
print("   ->\tctxt_x - ptxt_y = cpSub --(decr)--> ", _r(rcpSub))
print("   ->\tctxt_x * ptxt_y = cpMul --(decr)--> ", _r(rcpMul))
print(" Mean Squared error: ")
print("   ->\tmean(ctxt_x, ctxt_y) = c_mean --(decr)--> ", _r(rmean))
print("   ->\tmse(ctxt_x, ctxt_y)  = c_mse  --(decr)--> ", _r(rmse))
# sphinx_gallery_thumbnail_path = 'static/thumbnails/float.png'
# %%
