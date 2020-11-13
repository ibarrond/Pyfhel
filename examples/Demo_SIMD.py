"""
SIMD - Single Instruction Multiple Data
========================================

The present demo displays the use of Pyfhel to operate 
with multiple integers at once with the batching technique.
"""
# This example uses sympy for primality testing, but only if sympy is installed
def find_lib(lib=""):
    from importlib import util
    lib_spec = util.find_spec(lib)
    return lib_spec is not None
sympy_installed = find_lib("sympy")
if sympy_installed:
    from sympy import isprime

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class

import numpy as np


print("1. Creating Context and KeyGen in a Pyfhel Object. Careful about the context parameters!")
print("- p needs to be prime and p-1 must be multiple of 2*m.")
print("- m will determine the number of integer slots inside a single ciphertext")
HE = Pyfhel()           # Creating empty Pyfhel object
p = 1964769281
m = 8192
assert((p-1)%(2*m) == 0)
if (sympy_installed):
    assert (isprime(p))
HE.contextGen(p=p,m=m, base=2, sec=192, flagBatching=True)
HE.keyGen()             # Key Generation.
print("   We use Pyfhel.batchEnabled() to check if the current context allows batching, and getnSlots() to get the total number of integers that fit in a single ciphertext row (should be equal to m)")

print("2. Encrypting lists of Integers / NumPy arrays of size up to m. Empty slots are set to 0.")
list1 = [1,2,3,4,5,6]
list2 = [-2, -4, -6, -8, 0, 13]
ctxt1 = HE.encryptBatch(list1) # Encryption makes use of the public key
ctxt2 = HE.encryptBatch(list2) # For integers, encryptInt function is used.
print("    list1 ",list1,'-> ctxt1 ', type(ctxt1), str(ctxt1))
print("    list2 ",list2,'-> ctxt2 ', type(ctxt2), str(ctxt2))
arr1 = np.array([5,6,7,8], dtype=np.int64)
arr2 = np.array([-9, 10, -11, 12], dtype=np.int64)
ctxt3 = HE.encryptArray(arr1) 
ctxt4 = HE.encryptArray(arr2)

print("    arr1 ",arr1,'-> ctxt3 ', type(ctxt3), str(ctxt3))
print("    arr2 ",arr2,'-> ctxt4 ', type(ctxt4), str(ctxt4))


print("3. Operating in a SIMD manner with encrypted integers")
ctxtSum = ctxt1 + ctxt2
ctxtSub = ctxt3 - ctxt4
ctxtMul = ctxt1 * ctxt2
ctxtSum2 = ctxt3 + ctxt4
ctxtSub2 = ctxt1 - ctxt2      
ctxtMul2 = ctxt3 * ctxt2       

print("4. Decrypting results:")
resSum = HE.decryptBatch(ctxtSum) # Decryption must use the corresponding function
                                #  decryptInt.
resSub = HE.decryptBatch(ctxtSub) 
resMul = HE.decryptBatch(ctxtMul)
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum[:6])
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub[:6])
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul[:6])

resSum2 = np.array(HE.decryptBatch(ctxtSum2))
resSub2 = np.array(HE.decryptBatch(ctxtSub2))
resMul2 = np.array(HE.decryptBatch(ctxtMul2))
print("     addition:       decrypt(ctxt1 + ctxt3) =  ", resSum2[:4])
print("     substraction:   decrypt(ctxt3 - ctxt4) =  ", resSub2[:4])
print("     multiplication: decrypt(ctxt3 * ctxt2) =  ", resMul2[:4])



print("5. Trying out rotation:")
HE.rotateKeyGen(60)
print("     Initialized rotation keys: HE.rotateKeyGen(10)")
ctxt1_rot_r4 = ctxt1 >> 4   # Inplace equivalent: ctxt1 >>= 4 
ctxt2_rot_l2 = ctxt2 << 2   # Inplace equivalent: ctxt2 <<= 2

resrotr4 = np.array(HE.decryptBatch(ctxt1_rot_r4), dtype=np.int64)
resrotl2 = np.array(HE.decryptBatch(ctxt2_rot_l2), dtype=np.int64)

print("     ctxt1_rot_r4 = ctxt1 >> 4:  First 10 values:", resrotr4[:10])
print("                                 last 10 values:", resrotr4[-10:])
print("     ctxt2_rot_l2 = ctxt2 << 2:  First 10 values:", resrotl2[:10])
print("                                 last 10 values:", resrotl2[m//2-10:m//2])



# sphinx_gallery_thumbnail_path = 'static/thumbnails/simd.png'