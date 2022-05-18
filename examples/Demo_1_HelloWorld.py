"""
HelloWorld
===========================

This basic example shows the simplest use of the library by
encrypting two integers, operating with them (+,-,*) and decrypting
the results.
"""
# %%
# 1. Imports
# ---------------------------
# We start by importing the library with the three main classes:
#
# * Pyfhel class contains most of the functions.
# * PyPtxt is the plaintext class
# * PyCtxt is the ciphertext class
import numpy as np
from Pyfhel import Pyfhel
print("1. Import Pyfhel class, and numpy for the inputs to encrypt.")
# %%
# 2. Context and key setup
# ---------------------------
# We will start the Helloworld by generating a context and a public/secret key pair.
# This is all managed by a Pyfhel instance under the hood.
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(scheme='bfv', n=2**14, t_bits=20)  # Generate context for 'bfv'/'ckks' scheme
                        # The n defines the number of plaintext slots.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_2, Demo_3, and Pyfhel.contextGen()
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
# %%
# The best way to obtain information from a created Pyfhel object is to print it:
print("2. Context and key setup")
print(HE)

# %%
# 3. Integer Encryption
# ---------------------------
# we will define two integers and encrypt them using `encryptInt`:
integer1 = np.array([127], dtype=np.int64)
integer2 = np.array([-2], dtype=np.int64)
ctxt1 = HE.encryptInt(integer1) # Encryption makes use of the public key
ctxt2 = HE.encryptInt(integer2) # For integers, encryptInt function is used.
print("3. Integer Encryption, ")
print("    int ",integer1,'-> ctxt1 ', type(ctxt1))
print("    int ",integer2,'-> ctxt2 ', type(ctxt2))
# %%
# # The best way to obtain information from a ciphertext is to print it:
print(ctxt1)
print(ctxt2)

# %%
# 4. Operating with encrypted integers
# --------------------------------------
# Relying on the context defined before, we will now operate
# (addition, substaction, multiplication) the two ciphertexts:
ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for inplace operation
ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for inplace operation
ctxtMul = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for inplace operation
print("4. Operating with encrypted integers")
print(f"Sum: {ctxtSum}")
print(f"Sub: {ctxtSub}")
print(f"Mult:{ctxtMul}")

# %%
# 5.  Decrypting integers
# ---------------------------
# Once we're finished with the encrypted operations, we can use
# the Pyfhel instance to decrypt the results using `decryptInt`:
resSum = HE.decryptInt(ctxtSum) # Decryption must use the corresponding function
                                #  decryptInt.
resSub = HE.decryptInt(ctxtSub)
resMul = HE.decryptInt(ctxtMul)
print("#. Decrypting result:")
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)



# sphinx_gallery_thumbnail_path = 'static/thumbnails/helloworld.png'
