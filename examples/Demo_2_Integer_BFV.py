"""
Integer FHE with BFV scheme
========================================

Integer FHE Demo for Pyfhel, covering all the posibilities offered by 
the BFV scheme (see https://eprint.iacr.org/2012/144.pdf).
"""

import numpy as np
from Pyfhel import Pyfhel

# %%
# 1. Context and key setup
# ---------------------------
# We now investigate the different parameters that can be set for the BFV scheme.
HE = Pyfhel()           # Creating empty Pyfhel object
bfv_params = {
    'scheme': 'BFV',    # can also be 'bfv'
    'n': 2**12,         # Polynomial modulus degree, the num. of slots per plaintext,
                        #  of elements to be encoded in a single ciphertext. 
                        #  Typ. 2^D for D in [10, 16]
    't': 65537,         # Plaintext modulus. Encrypted operations happen modulo t
                        #  Must be prime such that t-1 be divisible by 2^N.
    't_bits': 16,       # Number of bits in t. Used to generate a suitable value 
                        #  for t. Overrides t if specified.
    'sec': 128,         # Security parameter. The equivalent length of AES key in bits.
                        #  Sets the ciphertext modulus q, can be one of {128, 192, 256}
                        #  More means more security but also slower computation.
}
HE.contextGen(**bfv_params)  # Generate context for bfv scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys


# %%
# 2. Integer Array Encoding & Encryption
# ---------------------------
# we will define two integer arrays, encode and encrypt them:
# arr1 = [0, 1, ... n-1] (length n)
# arr2 = [-t//2] (length 1)

arr1 = np.arange(bfv_params['n'], dtype=np.int64)    # Max possible value is t/2-1. Always use type int64!
arr2 = np.array([-bfv_params['t']//2], dtype=np.int64)  # Min possible value is -t/2. 

ptxt1 = HE.encodeInt(arr1)   # Creates a PyPtxt plaintext with the encoded arr1
ptxt2 = HE.encodeInt(arr2)   # plaintexts created from arrays shorter than 'n' are filled with zeros.

ctxt1 = HE.encryptPtxt(ptxt1) # Encrypts the plaintext ptxt1 and returns a PyCtxt
ctxt2 = HE.encryptPtxt(ptxt2) #  Alternatively you can use HE.encryptInt(arr2)

# Otherwise, a single call to `HE.encrypt` would detect the data type,
#  encode it and encrypt it
#> ctxt1 = HE.encrypt(arr1)

print("2. Integer Encoding & Encryption, ")
print("->\tarr1 ", arr1,'\n\t==> ptxt1 ', ptxt1,'\n\t==> ctxt1 ', ctxt1)
print("->\tarr2 ", arr2,'\n\t==> ptxt2 ', ptxt2,'\n\t==> ctxt2 ', ctxt2)

# %%
# 3. Securely operating on encrypted ingeger arrays
# ---------------------------
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
cPow  = ctxt1**3            # Calls HE.power(ctxt1, 3, in_new_ctxt=True)
                            #  `ctxt1 **= 3` for inplace operation
cRotR = ctxt1 >> 4          # Calls HE.rotate(ctxt1, k=4, in_new_ctxt=True)
                            #  `ctxt1 >>= 4` for inplace operation
cRotL = ctxt1 << 4          # Calls HE.rotate(ctxt1, k=-4, in_new_ctxt=True)
                            #  `ctxt1 <<= 4` for inplace operation

# Ciphetext-plaintext ops
cpSum = ctxt1 + ptxt2       # Calls HE.add_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 += ctxt2` for inplace operation
cpSub = ctxt1 - ptxt2       # Calls HE.sub_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 -= ctxt2` for inplace operation
cpMul = ctxt1 * ptxt2       # Calls HE.multiply_plain(ctxt1, ptxt2, in_new_ctxt=True)
                            # `ctxt1 *= ctxt2` for inplace operation

# %%
# 4. Relinearization: What, why, when
# ---------------------------
# 
print("4. Operating with encrypted integers")
print(f"Sum: {ctxtSum}")
print(f"Sub: {ctxtSub}")
print(f"Mult:{ctxtMul}")

print("6. Encrypting/Decrypting all plaintexts using encryptPtxt/decryptPtxt")
print("      HE.encrypt could also do, detecting PyPtxt as a valid type")
print("      Just remember to operate only with ciphertexts with same encoding")
print("     ATTENTION: HE.decrypt will directly decrypt AND decode if used with decode_value=True! ")
ctxt1 = HE.encryptPtxt(ptxt_i1)
ctxt2 = HE.encrypt(ptxt_f1)
ctxt3 = HE.encryptPtxt(ptxt_b1)
ctxt4 = HE.encrypt(ptxt_a1)

integer1 = HE.decrypt(ctxt1)
float1 = HE.decrypt(ctxt2)
vector1 = HE.decrypt(ctxt3)

print("7. Decoding values")
res_i1 = HE.decodeInt(ptxt_i1) # Decoding must use the corresponding decodeing
res_f1 = HE.decodeFrac(ptxt_f1) # Decoding must use the corresponding decodeing
res_b1 = HE.decodeBatch(ptxt_b1) # Decoding must use the corresponding decodeing
res_a1 = HE.decodeArray(ptxt_a1) # Decoding must use the corresponding decodeing

print("    Integer (encodeInt, ENCODING_t.INTEGER, decodeInt)")
print("      decode(ptxt_i1) =  ", res_i1)

print("    Float (encodeFrac, ENCODING_t.FRACTIONAL, decodeFrac)")
print("     decode(ptxt_f1) =  ", res_f1)

print("    Batched list (encodeBatch, ENCODING_t.BATCH, decodeBatch)")
print("     decode(ptxt_b1) =  ", res_b1[:len(vector2)])

print("    NumPy 1D vector (encodeArray, ENCODING_t.BATCH, decodeArray)")
print("     decode(ptxt_a1) =  ", res_a1[:len(array2)])

print("8. EXTRA: you can use encode/decode function to guess type")
print("    HE.encode(integer1|float1|vector1|array1)")
print("       delegates into encodeInt|encodeFrac|encodeBatch|encodeArray depending on type")
print("    HE.decode(PyPtxt)")
print("       uses recorded ENCODING_t type to correctly decode")
ptxt1 = HE.encode(integer2)
ptxt2 = HE.encode(float2)
ptxt3 = HE.encode(array2)

integer2 = HE.decode(ptxt1)
float2 =   HE.decode(ptxt2)
array2 =   HE.decode(ptxt3)



# sphinx_gallery_thumbnail_path = 'static/thumbnails/encoding.png'
# %%
