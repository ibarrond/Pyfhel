"""
Pyfhel with Numpy
==============================

This demo shows how to leverage on the np.ndarray container to perform
encrypted operations over vectors of ciphertexts.
"""

import numpy as np

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("===================== Pyfhel with Numpy ======================")
print("==============================================================")


print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537)  # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters.py, and
                        #  in the docs of the function (link to docs in README)
HE.keyGen()             # Key Generation.
print(HE)

print("2. Encrypting two arrays of integers.")
print("    For this, you need to create empty arrays in numpy and assign them the cyphertexts")
array1 = np.array([1,3,5,7,9])
array2 = np.array([-2, 4, -6, 8,-10])
arr_ctxt1 = np.empty(len(array1),dtype=PyCtxt)
arr_ctxt2 = np.empty(len(array1),dtype=PyCtxt)

# Encrypting! This can be parallelized!
for i in np.arange(len(array1)):
    arr_ctxt1[i] = HE.encryptInt(array1[i])
    arr_ctxt2[i] = HE.encryptInt(array2[i])

print("    array1: ",array1,'-> ctxt1 ', type(arr_ctxt1), ', dtype:', arr_ctxt1.dtype)
print("    array2: ",array2,'-> ctxt2 ', type(arr_ctxt2), ', dtype:', arr_ctxt2.dtype)

print("3. Vectorized operations with encrypted arrays of PyCtxt")
ctxtSum = arr_ctxt1 + arr_ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
ctxtSub = arr_ctxt1 - arr_ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation
ctxtMul = arr_ctxt1 * arr_ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation


print("4. Decrypting results:")
resSum = [HE.decryptInt(ctxtSum[i]) for i in np.arange(len(ctxtSum))]
resSub = [HE.decryptInt(ctxtSub[i]) for i in np.arange(len(ctxtSub))] 
resMul = [HE.decryptInt(ctxtMul[i]) for i in np.arange(len(ctxtMul))]
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)



# sphinx_gallery_thumbnail_path = 'static/thumbnails/numpy.png'