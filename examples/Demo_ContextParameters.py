"""
Context Parameters in Pyfhel
========================================

Context Parameters shows how several parameters affect performance.
"""
# 
#  TODO: Finish for all parameters. Show possible values of each.

import time

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("================== Pyfhel CONTEXT PARAMETERS =================")
print("==============================================================")


print("1. p (long): Plaintext modulus. All operations are modulo p. ")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537)  # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
HE.keyGen()             # Key Generation.


print("2. m (long=2048): Polynomial coefficient modulus.")
print("   Higher allows more encrypted operations. In batch mode it is the number of integers per ciphertext.")

def time_demo_helloworld(integer1=127, integer2=-2):
    start = time.time()
    ctxt1 = HE.encryptInt(integer1) # Encryption makes use of the public key
    ctxt2 = HE.encryptInt(integer2) # For integers, encryptInt function is used.
    ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
    ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation
    ctxtMul = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation
    resSum = HE.decryptInt(ctxtSum)
    resSub = HE.decryptInt(ctxtSub) 
    resMul = HE.decryptInt(ctxtMul)
    end = time.time()
    print(f"Elapsed time: {end - start}")
    results = (resSum==125, resSub==129, resMul==-254)
    return end - start, results


# sphinx_gallery_thumbnail_path = 'static/thumbnails/contextParameters.jpg'