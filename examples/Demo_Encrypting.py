"""
Encrypting with Pyfhel
========================================

Encrypting Demo for Pyfhel, covering the different ways of encrypting
and decrypting.
"""



from Pyfhel import Pyfhel, PyPtxt, PyCtxt

print("==============================================================")
print("===================== Pyfhel ENCRYPTING ======================")
print("==============================================================")


print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()                                       # Creating empty Pyfhel object
HE.contextGen(p=65537, m=2048, base=3, flagBatching=True)   # Generating context. 
# The values of p and m are chosen to enable batching (see Demo_Batching_SIMD.py)
HE.keyGen()                                         # Key Generation.

print("2. Encrypting integers with encryptInt")
integer1 = 94
integer2 = -235
ctxt_i1 = HE.encryptInt(integer1)   # Encrypting integer1 in a new PyCtxt with encryptInt
ctxt_i2 = PyCtxt()                  # Empty ciphertexts have no encoding type.
print("    Empty created ctxt_i2: ",   str(ctxt_i2))
HE.encryptInt(integer2, ctxt_i2)    # Encrypting integer2 in an existing PyCtxt
print("    int ",integer1,'-> ctxt_i1 ', str(ctxt_i1))
print("    int ",integer2,'-> ctxt_i2 ', str(ctxt_i2))

print("3. Encrypting floating point values with encryptFrac")
float1 = 3.5
float2 = -7.8
ctxt_f1 = HE.encryptFrac(float1)     # Encrypting float1 in a new PyCtxt with encryptFrac
ctxt_f2 = PyCtxt()
HE.encryptFrac(float2, ctxt_f2)     # Encrypting float2 in an existing PyCtxt
print("    float ",float1,'-> ctxt_f1 ', str(ctxt_f1))
print("    float ",float2,'-> ctxt_f2 ', str(ctxt_f2))

print("4. Encrypting lists of integers using batching with encryptBatch")
vector1 = [ 1, 2, 3, 4, 5, 6]
vector2 = [-2, 3,-4,-3, 2,-1]
ctxt_b1 = HE.encryptBatch(vector1)  # Encrypting vector1 in a new PyCtxt with encryptBatch
ctxt_b2 = PyCtxt()                 
HE.encryptBatch(vector2, ctxt_b2)    # Encrypting vector2 in an existing PyCtxt
print("    list ",vector1,'-> ctxt_b1 ', str(ctxt_b1))
print("    list ",vector2,'-> ctxt_b2 ', str(ctxt_b2))

print("5. Encrypting numpy 1D integer vectors using batching encryptArray")
import numpy as np
array1 = np.array([-6, -5, -4, -3, -2, -1],dtype=np.int64)
array2 = np.array([12, 15, 18, 21, 24, 27],dtype=np.int64)
ctxt_a1 = HE.encryptArray(array1)   # Encrypting array1 in a new PyCtxt with encryptArray
ctxt_a2 = PyCtxt()                
HE.encryptArray(array2, ctxt_a2)    # Encrypting vector2 in an existing PyCtxt
print("    array ",array1,'-> ctxt_a1 ', str(ctxt_a1))
print("    array ",array2,'-> ctxt_a2 ', str(ctxt_a2))

print("6. Operations in the encrypted domain")
ctxt_iadd = ctxt_i1 + ctxt_i2     # `ctxt_i1 += ctxt_i2` for quicker inplace operation
ctxt_isub = ctxt_i1 - ctxt_i2     # `ctxt_i1 -= ctxt_i2` for quicker inplace operation
ctxt_imul = ctxt_i1 * ctxt_i2     # `ctxt_i1 *= ctxt_i2` for quicker inplace operation

ctxt_fadd = ctxt_f1 + ctxt_f2     # `ctxt_f1 += ctxt_f2` for quicker inplace operation
ctxt_fsub = ctxt_f1 - ctxt_f2     # `ctxt_f1 -= ctxt_f2` for quicker inplace operation
ctxt_fmul = ctxt_f1 * ctxt_f2     # `ctxt_f1 *= ctxt_f2` for quicker inplace operation

ctxt_badd = ctxt_b1 + ctxt_b2     # `ctxt_b1 += ctxt_b2` for quicker inplace operation
ctxt_bsub = ctxt_b1 - ctxt_b2     # `ctxt_b1 -= ctxt_b2` for quicker inplace operation
ctxt_bmul = ctxt_b1 * ctxt_b2     # `ctxt_b1 *= ctxt_b2` for quicker inplace operation

ctxt_aadd = ctxt_a1 + ctxt_a2     # `ctxt_a1 += ctxt_a2` for quicker inplace operation
ctxt_asub = ctxt_a1 - ctxt_a2     # `ctxt_a1 -= ctxt_a2` for quicker inplace operation
ctxt_amul = ctxt_a1 * ctxt_a2     # `ctxt_a1 *= ctxt_a2` for quicker inplace operation

ctxt_abadd = ctxt_a1 + ctxt_b2    # `ctxt_a1 += ctxt_b2` for quicker inplace operation
ctxt_absub = ctxt_a1 - ctxt_b2    # `ctxt_a1 -= ctxt_b2` for quicker inplace operation
ctxt_abmul = ctxt_a1 * ctxt_b2    # `ctxt_a1 *= ctxt_b2` for quicker inplace operation


print("    PyCtxt Ciphertexts can only be operated with each other if:")
print("    I.  They have the same encoding type.")
print("        int                           - ENCODING_t.INTEGER")
print("        float                         - ENCODING_t.FRACTIONAL")
print("        list[int] and np.array([int]) - ENCODING_t.BATCH")
print("    II. They were encrypted with the same public key and context")


print("7. Decrypting result:")
res_iSum = HE.decryptInt(ctxt_iadd) # Decryption must use the corresponding decrypting
res_iSub = HE.decryptInt(ctxt_isub) #  function, depending on the encoding type
res_iMul = HE.decryptInt(ctxt_imul)

res_fSum = HE.decryptFrac(ctxt_fadd) # Decryption must use the corresponding decrypting
res_fSub = HE.decryptFrac(ctxt_fsub) #  function, depending on the encoding type
res_fMul = HE.decryptFrac(ctxt_fmul)

res_bSum = HE.decryptBatch(ctxt_badd) # Decryption must use the corresponding decrypting
res_bSub = HE.decryptBatch(ctxt_bsub) #  function, depending on the encoding type
res_bMul = HE.decryptBatch(ctxt_bmul)

res_aSum = HE.decryptArray(ctxt_aadd) # Decryption must use the corresponding decrypting
res_aSub = HE.decryptArray(ctxt_asub) #  function, depending on the encoding type
res_aMul = HE.decryptArray(ctxt_amul)

res_abSum = HE.decryptBatch(ctxt_abadd) # Decryption must use the corresponding decrypting
res_abSub = HE.decryptBatch(ctxt_absub) #  function, depending on the encoding type
res_abMul = HE.decryptArray(ctxt_abmul)

print("    Integer (encryptInt, ENCODING_t.INTEGER, decryptInt)")
print("     addition:       decrypt(ctxt_i1 + ctxt_i2) =  ", res_iSum)
print("     substraction:   decrypt(ctxt_i1 - ctxt_i2) =  ", res_iSub)
print("     multiplication: decrypt(ctxt_i1 + ctxt_i2) =  ", res_iMul)

print("    Float (encryptFrac, ENCODING_t.FRACTIONAL, decryptFrac)")
print("     addition:       decrypt(ctxt_f1 + ctxt_f2) =  ", res_fSum)
print("     substraction:   decrypt(ctxt_f1 - ctxt_f2) =  ", res_fSub)
print("     multiplication: decrypt(ctxt_f1 + ctxt_f2) =  ", res_fMul)

print("    Batched list (encryptBatch, ENCODING_t.BATCH, decryptBatch)")
print("     addition:       decrypt(ctxt_b1 + ctxt_b2) =  ", res_bSum[:len(vector1)])
print("     substraction:   decrypt(ctxt_b1 - ctxt_b2) =  ", res_bSub[:len(vector1)])
print("     multiplication: decrypt(ctxt_b1 + ctxt_b2) =  ", res_bMul[:len(vector1)])

print("    NumPy 1D vector (encryptArray, ENCODING_t.BATCH, decryptArray)")
print("     addition:       decrypt(ctxt_a1 + ctxt_a2) =  ", np.array(res_aSum[:len(array1)]))
print("     substraction:   decrypt(ctxt_a1 - ctxt_a2) =  ", np.array(res_aSub[:len(array1)]))
print("     multiplication: decrypt(ctxt_a1 + ctxt_a2) =  ", np.array(res_aMul[:len(array1)]))

print("    List & np 1D vec (..., ENCODING_t.BATCH, ...)")
print("     addition:       decrypt(ctxt_a1 + ctxt_b2) =  ", res_abSum[:len(vector1)])
print("     substraction:   decrypt(ctxt_a1 - ctxt_b2) =  ", res_abSub[:len(vector1)])
print("     multiplication: decrypt(ctxt_a1 + ctxt_b2) =  ", np.array(res_abMul[:len(vector1)]))


print("8. EXTRA: you can encrypt/decrypt function to guess type")
print("    HE.encrypt(integer1|float1|vector1|array1)")
print("       delegates into encryptInt|encryptFrac|EncryptBatch|envryptArray depending on type")
print("    HE.decrypt(PyCtxt)")
print("       uses recorded ENCODING_t type to correctly decrypt")
ctxt1 = HE.encrypt(integer1)
ctxt2 = HE.encrypt(float1)
ctxt3 = HE.encrypt(array1)

integer1 = HE.decrypt(ctxt1)
float1 =   HE.decrypt(ctxt2)
array1 =   HE.decrypt(ctxt3)



# sphinx_gallery_thumbnail_path = 'static/thumbnails/encrypting.jpg'