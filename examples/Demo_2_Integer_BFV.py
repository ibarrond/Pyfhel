"""
Integer FHE with BFV scheme
========================================

Integer FHE Demo for Pyfhel, covering all the posibilities offered by 
the BFV scheme (see https://eprint.iacr.org/2012/144.pdf).
"""

import numpy as np
from Pyfhel import Pyfhel

# %%
# 2. Context and key setup
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
                        #  for t. Overrides the previous value.
    'sec': 128,         # Security parameter. The equivalent length of AES key in bits.
                        #  Sets the ciphertext modulus q, can be one of {128, 192, 256}
                        #  More means more security but also slower computation.
}
HE.contextGen(**bfv_params)  # Generate context for bfv scheme
HE.keyGen()             # Key Generation: generates a pair of public/secret keys


# %%
# 2. Integer Array Encryption
# ---------------------------
# we will define two integer arrays, encode and encrypt them:
arr1 = np.arange(bfv_params['n'], dtype=np.int64)    # Max possible value is t/2-1. Use type int64!
arr2 = np.array([-bfv_params['t']//2], dtype=np.int64)  # Min possible value is -t/2. 

ptxt1 = HE.encodeInt(arr1)   # Creates a PyPtxt plaintext with the encoded arr1
ptxt2 = HE.encodeInt(arr2)   # plaintexts created from arrays shorter than 'n' are filled with zeros.

ctxt1 = HE.encryptPtxt(ptxt1) # Encrypts the plaintext ptxt1 and returns a PyCtxt
ctxt2 = HE.encryptPtxt(ptxt2) #  Alternatively you can use HE.encryptInt(arr2)
print("3. Integer Encryption, ")
print("\tarr1 ", arr1,'\n\t==> ptxt1 ', ptxt1,'\n\t==> ctxt1 ', ctxt1)
print("    arr2 ", arr2,'\n\t==> ptxt2 ', ptxt2,'\n\t==> ctxt2 ', ctxt2)

# %% WIP!!!!!!!!!!!! CONTINUE HERE

print("2. Encoding integers with encodeInt")
integer1 = 45
integer2 = -32
ptxt_i1 = HE.encodeInt(integer1)   # Encoding integer1 in a new PyPtxt
ptxt_i2 = PyPtxt()                 # Empty plaintexts have no encoding type.
print("    Empty created ptxt_i2: ",   str(ptxt_i2))
HE.encodeInt(integer2, ptxt_i2)    # Encoding integer2 in an existing PyPtxt
print("    int ",integer1,'-> ptxt_i1 ', str(ptxt_i1))
print("    int ",integer2,'-> ptxt_i2 ', str(ptxt_i2))

print("3. Encoding floating point values with encodeFrac")
float1 = 3.5
float2 = -7.8
ptxt_f1 = HE.encodeFrac(float1)     # Encoding float1 in a new PyPtxt with encodeFrac
ptxt_f2 = PyPtxt()
HE.encodeFrac(float2, ptxt_f2)     # Encoding float2 in an existing PyPtxt
print("    float ",float1,'-> ptxt_f1 ', str(ptxt_f1))
print("    float ",float2,'-> ptxt_f2 ', str(ptxt_f2))

print("4. Encoding lists of integers using batching with encodeBatch")
vector1 = [ 1, 2, 3, 4, 5, 6]
vector2 = [-2, 3,-4,-3, 2,-1]
ptxt_b1 = HE.encodeBatch(vector1)  # Encoding vector1 in a new PyPtxt with encodeBatch
ptxt_b2 = PyPtxt()                 
HE.encodeBatch(vector2, ptxt_f2)    # Encoding vector2 in an existing PyPtxt
print("    list ",vector1,'-> ptxt_b1 ', str(ptxt_b1))
print("    list ",vector2,'-> ptxt_b2 ', str(ptxt_b2))

print("5. Encoding numpy 1D integer vectors using batching encodeArray")
import numpy as np
array1 = np.array([-6, -5, -4, -3, -2, -1],dtype=np.int64)
array2 = np.array([12, 15, 18, 21, 24, 27],dtype=np.int64)
ptxt_a1 = HE.encodeArray(array1)   # Encoding array1 in a new PyPtxt with encodeArray
ptxt_a2 = PyPtxt()                
HE.encodeArray(array2, ptxt_a2)    # Encoding vector2 in an existing PyPtxt
print("    array ",array1,'-> ptxt_a1 ', str(ptxt_a1))
print("    array ",array2,'-> ptxt_a2 ', str(ptxt_a2))

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
