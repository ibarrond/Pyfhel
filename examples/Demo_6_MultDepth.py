"""
MultDepth and Relineraization
==============================

This demo focuses on managing ciphertext size and noise budget.

Each ciphertext can be seen as (oversimplifying a bit) a polynomial with noise.
When you perform encrypted multiplication, the size of the output polynomial grows
based on the size of the tho muliplicands, which increases its memory footprint
and slows down operations. In order to keep ciphertext sizes low (min. 2), it
is recommended to relinearize after each multiplication, effectively shrinking
the ciphertext back to minimum size.

Besides this, the noise inside the ciphertext grows greatly when multiplying.
Each ciphertext is given a noise budget when first encrypted, which decreases
irreversibly for each multiplication. If the noise budget reaches zero, the
resultin ciphertext cannot be decrypted correctly anymore.
"""
# %%
# ---------------------------------------------------------------------------- #
# A) BFV - MULTIPLICATIVE DEPTH WITH INTEGERS
# ---------------------------------------------------------------------------- #
# A1. Context and key setup
# ---------------------------
# Feel free to change these parameters!
import numpy as np
from Pyfhel import Pyfhel
HE = Pyfhel(key_gen=True, context_params= {
    'scheme': 'BFV',
    'n': 2**13,         # num. of slots per plaintext. Higher n yields higher noise 
                        #  budget, but operations take longer.
    't': 65537,         # Plaintext modulus (and bits). Higher t yields higher noise
    't_bits': 20,       #  budget, but operations take longer.
    'sec': 128,         # Security parameter.
})
HE.relinKeyGen()

print("\nA1. BFV context generation")
print(f"\t{HE}")

# %%
# 2. BFV Array Encoding & Encryption
# -----------------------------------------
# We will define two 1D integer arrays, encode and encrypt them:
# arr1 = [0, 1, ... n-1]
# arr2 = [-t//2, -1, 1, 0, 0..., 0]  

arr1 = np.arange(HE.n, dtype=np.int64)
arr2 = np.array([1, -1, 1], dtype=np.int64) 

ctxt1 = HE.encryptInt(arr1)
ctxt2 = HE.encryptInt(arr2)

print("\nA2. Integer Encryption")
print("->\tarr1 ", arr1,'\n\t==> ctxt1 ', ctxt1)
print("->\tarr2 ", arr2,'\n\t==> ctxt2 ', ctxt2)


# %%
# 3. BFV: Securely multiplying as much as we can
# -------------------------------------------------
# You can measure the noise level using HE.noise_level(ctxt).
# IMPORTANT! To get the noise Level you need the private key! otherwise the only
# way to know if above the noise is to decrypt the ciphertext and check the result.

print("A3. Securely multiplying as much as we can")
step = 0
lvl = HE.noise_level(ctxt1)
while lvl > 0:
    print(f"\tStep {step}: noise_lvl {lvl}, res {HE.decryptInt(ctxt1)[:4]}")
    step += 1
    ctxt1 *= ctxt2    # Multiply in-place
    ctxt1 = ~(ctxt1)  # Always relinearize after each multiplication!
    lvl = HE.noise_level(ctxt1)
print(f"\tFinal Step {step}: noise_lvl {lvl}, res {HE.decryptInt(ctxt1)[:4]}")
print("---------------------------------------")

          
# %%
# ---------------------------------------------------------------------------- #
# B) CKKS - MULTIPLICATIVE DEPTH WITH FIXED-POINTS
# ---------------------------------------------------------------------------- #
# In this case we don't have a noise_level operation to check the current noise,
# since the noise is considered as part of the encoding and adds up to a loss in
# precision of the encoded values.
# However, we can precisely control the maximum # of multiplications by setting qi.
#
# B1. Context and key setup
# ---------------------------
import numpy as np
from Pyfhel import Pyfhel

# Feel free to change this number!
n_mults = 8

HE = Pyfhel(key_gen=True, context_params={
    'scheme': 'CKKS',
    'n': 2**14,         # For CKKS, n/2 values can be encoded in a single ciphertext. 
    'scale': 2**30,     # Each multiplication grows the final scale
    'qi': [60]+ [30]*n_mults +[60] # Number of bits of each prime in the chain. 
                        # Intermediate prime sizes should be close to log2(scale).
                        # One per multiplication! More/higher qi means bigger 
                        #  ciphertexts and slower ops.
})
HE.relinKeyGen()
print("\nB1. CKKS context generation")
print(f"\t{HE}")

# %%
# B2. CKKS Array Encoding & Encryption
# ----------------------------------------
arr_x = np.array([1.1, 2.2, -3.3], dtype=np.float64) 
arr_y = np.array([1, -1, 1], dtype=np.float64)

ctxt_x = HE.encryptFrac(arr_x)
ctxt_y = HE.encryptFrac(arr_y)

print("\nB2. Fixed-point Encoding & Encryption, ")
print("->\tarr_x ", arr_x,'\n\t==> ctxt_x ', ctxt_x)
print("->\tarr_y ", arr_y,'\n\t==> ctxt_y ', ctxt_y)

# %%
# B3. Multiply n_mult times!
# -----------------------------
# Besides rescaling, we also need to perform rescaling & mod switching. Luckily 
# Pyfhel does it for us by calling HE.align_mod_n_scale() before each operation.

_r = lambda x: np.round(x, decimals=6)[:4]
print(f"B3. Securely multiplying {n_mults} times!")
for step in range(1,n_mults+1):
    ctxt_x *= ctxt_y    # Multiply in-place --> implicit align_mod_n_scale()
    ctxt_x = ~(ctxt_x)  # Always relinearize after each multiplication!
    print(f"\tStep {step}:  res {_r(HE.decryptFrac(ctxt_x))}")
try:
    ctxt_x *= ctxt_y
except ValueError as e:
    assert str(e)=='scale out of bounds'
    print(f"If we multiply further we get: {str(e)}")
print("---------------------------------------")



# sphinx_gallery_thumbnail_path = 'static/thumbnails/multDepth.jpg'