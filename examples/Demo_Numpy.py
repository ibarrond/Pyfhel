"""
Pyfhel with Numpy and Pickle
==============================

This demo shows how to leverage on the np.ndarray container to perform
encrypted operations over vectors of ciphertexts. We will use pickle
to simulate data tramsnission by serializing it.
"""

import numpy as np

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("================ Pyfhel with Numpy and Pickle ================")
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
array1 = np.array([1.3,3.4,5.8,7.1,9.2])
array2 = np.array([-2., 4., -6., 8.,-10.])
arr_gen1 = np.empty(len(array1),dtype=PyCtxt)
arr_gen2 = np.empty(len(array1),dtype=PyCtxt)

# Encrypting! This can be parallelized!
for i in np.arange(len(array1)):
    arr_gen1[i] = HE.encryptFrac(array1[i])
    arr_gen2[i] = HE.encryptFrac(array2[i])

print("    array1: ",array1,'-> ctxt1 ', type(arr_gen1), ', dtype:', arr_gen1.dtype)
print("    array2: ",array2,'-> ctxt2 ', type(arr_gen2), ', dtype:', arr_gen2.dtype)

print("3. Sending the data and the pyfhel object to operate.")
# NETWORK! Pickling
# Pickling to send it over the network. Each PyCtxt can be pickled individually.
# arr1_pk and arr2_pk are strings that could be sent over the network or saved.
import pickle
arr1_pk = pickle.dumps(arr_gen1)
arr2_pk = pickle.dumps(arr_gen2)
pyfh_pk = pickle.dumps(HE)

# Here you would send the pickled strings over the network

# Retrieve data
arr_ctxt1 = pickle.loads(arr1_pk)
arr_ctxt2 = pickle.loads(arr2_pk)
HE2 = pickle.loads(pyfh_pk)

# Reassign Pyfhel instance. Pickling doesn't keep the pyfhel instance
for ctxt in arr_ctxt1:
    ctxt._pyfhel = HE2

print("4. Vectorized operations with encrypted arrays of PyCtxt")
ctxtSum = arr_ctxt1 + arr_ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
ctxtSub = arr_ctxt1 - arr_ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation
ctxtMul = arr_ctxt1 * arr_ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation

# Here you could send back the resulting ciphertexts pickling them.


print("4. Decrypting results:")
resSum = [HE.decryptFrac(ctxtSum[i]) for i in np.arange(len(ctxtSum))]
resSub = [HE.decryptFrac(ctxtSub[i]) for i in np.arange(len(ctxtSub))] 
resMul = [HE.decryptFrac(ctxtMul[i]) for i in np.arange(len(ctxtMul))]
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)



# sphinx_gallery_thumbnail_path = 'static/thumbnails/numpy.png'