"""
Pyfhel Codecs
========================================

Encoding Demo for Pyfhel, covering the different ways of encoding
and decodeing.
"""


from Pyfhel import Pyfhel, PyPtxt, PyPtxt

print("==============================================================")
print("====================== Pyfhel ENCODING =======================")
print("==============================================================")


print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()                                       # Creating empty Pyfhel object
HE.contextGen(p=65537, m=1024, flagBatching=True)   # Generating context. 
# The values of p and m are chosen to enable batching (see Demo_Batching_SIMD.py)
HE.keyGen()                                         # Key Generation.

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