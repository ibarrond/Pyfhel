# Encrypting Demo for Pyfhel, covering the different ways of encrypting
#   and decrypting.

from Pyfhel import Pyfhel, PyPtxt, PyCtxt

print("==============================================================")
print("===================== Pyfhel ENCRYPTING ======================")
print("==============================================================")


print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()                                       # Creating empty Pyfhel object
HE.contextGen(p=65537, m=1024, flagBatching=True)   # Generating context. 
# The values of p and m are chosen to enable batching (see Demo_Batching_SIMD.py)
HE.keyGen()                                         # Key Generation.

print("2. Encrypting integers")
integer1 = 94
integer2 = -235
ctxt_i1 = HE.encryptInt(integer1)   # Encrypting integer1 in a new PyCtxt with encryptInt
ctxt_i2 = PyCtxt()                  # Empty ciphertexts have no encoding type.
print("    Empty created ctxt_i2: ",   str(ctxt_i2))
HE.encryptInt(integer2, ctxt_i2)    # Encrypting integer2 in an existing PyCtxt
print("    int ",integer1,'-> ctxt_i1 ', str(ctxt_i1))
print("    int ",integer2,'-> ctxt_i2 ', str(ctxt_i2))

print("3. Encrypting floating point values")
float1 = 3.5
float2 = -7.8
ctxt_f1 = HE.encryptInt(float1)     # Encrypting float1 in a new PyCtxt with encryptFrac
ctxt_f2 = PyCtxt()
HE.encryptFrac(float2, ctxt_f2)     # Encrypting float2 in an existing PyCtxt
print("    float ",float1,'-> ctxt_f1 ', str(ctxt_f1))
print("    float ",float2,'-> ctxt_f2 ', str(ctxt_f2))

print("4. Encrypting lists of integers using batching")
vector1 = [ 1, 2, 3, 4, 5, 6]
vector2 = [-2, 3,-4,-3, 2,-1]
ctxt_b1 = HE.encryptBatch(vector1)  # Encrypting vector1 in a new PyCtxt with encryptBatch
ctxt_b2 = PyCtxt()                 
HE.encryptBatch(vector2, ctxt_f2)    # Encrypting vector2 in an existing PyCtxt
print("    vector ",vector1,'-> ctxt_b1 ', str(ctxt_b1))
print("    vector ",vector2,'-> ctxt_b2 ', str(ctxt_b2))

print("5. Encrypting numpy 1D integer vectors using batching")
import numpy as np
array1 = np.array([-6, -5, -4, -3, -2, -1])
array2 = np.array([12, 15, 18, 21, 24, 27])
ctxt_a1 = HE.encryptArray(array1)   # Encrypting array1 in a new PyCtxt with encryptArray
ctxt_a2 = PyCtxt()                
HE.encryptArray(array2, ctxt_a2)    # Encrypting vector2 in an existing PyCtxt
print("    vector ",array1,'-> ctxt_a1 ', str(ctxt_a1))
print("    vector ",array2,'-> ctxt_a2 ', str(ctxt_a2))

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

ctxt_badd = ctxt_b1 + ctxt_b2     # `ctxt_b1 += ctxt_b2` for quicker inplace operation
ctxt_bsub = ctxt_b1 - ctxt_b2     # `ctxt_b1 -= ctxt_b2` for quicker inplace operation
ctxt_bmul = ctxt_b1 * ctxt_b2     # `ctxt_b1 *= ctxt_b2` for quicker inplace operation

ctxt_aadd = ctxt_a1 + ctxt_a2     # `ctxt_a1 += ctxt_a2` for quicker inplace operation
ctxt_asub = ctxt_a1 - ctxt_a2     # `ctxt_a1 -= ctxt_a2` for quicker inplace operation
ctxt_amul = ctxt_a1 * ctxt_a2     # `ctxt_a1 *= ctxt_a2` for quicker inplace operation

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

res_fSum = HE.decryptInt(ctxt_fadd) # Decryption must use the corresponding decrypting
res_fSub = HE.decryptInt(ctxt_fSub) #  function, depending on the encoding type
res_fMul = HE.decryptInt(ctxt_fmul)

res_bSum = HE.decryptInt(ctxt_badd) # Decryption must use the corresponding decrypting
res_bSub = HE.decryptInt(ctxt_bsub) #  function, depending on the encoding type
res_bMul = HE.decryptInt(ctxt_bmul)

res_aSum = HE.decryptInt(ctxt_aadd) # Decryption must use the corresponding decrypting
res_aSub = HE.decryptInt(ctxt_asub) #  function, depending on the encoding type
res_aMul = HE.decryptInt(ctxt_amul)

print("     addition:       decrypt(ctxt_i1 + ctxt_i2) =  ", resSum)
print("     substraction:   decrypt(ctxt_i1 - ctxt_i2) =  ", resSub)
print("     multiplication: decrypt(ctxt_i1 + ctxt_i2) =  ", resMul)

print("     addition:       decrypt(ctxt_f1 + ctxt_f2) =  ", resSum)
print("     substraction:   decrypt(ctxt_f1 - ctxt_f2) =  ", resSub)
print("     multiplication: decrypt(ctxt_f1 + ctxt_f2) =  ", resMul)

print("     addition:       decrypt(ctxt_b1 + ctxt_b2) =  ", resSum)
print("     substraction:   decrypt(ctxt_b1 - ctxt_b2) =  ", resSub)
print("     multiplication: decrypt(ctxt_b1 + ctxt_b2) =  ", resMul)

print("     addition:       decrypt(ctxt_a1 + ctxt_a2) =  ", resSum)
print("     substraction:   decrypt(ctxt_a1 - ctxt_a2) =  ", resSub)
print("     multiplication: decrypt(ctxt_a1 + ctxt_a2) =  ", resMul)
