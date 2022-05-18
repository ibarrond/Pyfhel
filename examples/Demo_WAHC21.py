"""
WAHC21
===========================

This demo includes all the code snippets from the WAHC21 Pyfhel paper (corresponding sections in parenthesis).
"""
# %% --------------------------------------------------
# 1. Setup and Parameters (Sec. 4.1)
# -----------------------------------------------------
# We start by importing the library with the three main classes:
# * Pyfhel class contains most of the functions.
# * PyPtxt is the plaintext class
# * PyCtxt is the ciphertext class
#
# Then we generate a context a context and a public/secret key pair.
#  -> This is all managed by a Pyfhel instance under the hood. 
from Pyfhel import Pyfhel, PyPtxt, PyCtxt

HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(scheme='BFV', n=4096, p_bits=20, sec=128)  # Generating context. The p defines the plaintext modulo.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters, and
                        #  in Pyfhel.contextGen()
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
print("1. Setup: ", HE)


# %% --------------------------------------------------
# 2. Encryption & Decryption (Sec. 4.2)
# -----------------------------------------------------
# We show how to encrypt and decrypt a plaintex, including encoding and decoding.
integer = 45 
int_ptxt = HE.encode(integer)   # PyPtxt [45, 45,...]
int_ctxt = HE.encrypt(int_ptxt) # PyCtxt

import numpy as np
np_array = np.array([6, 5, 4, 3, 2, 1],dtype=np.int64)
array_ptxt = HE.encode(np_array)    # Accepts list too
array_ctxt = HE.encrypt(array_ptxt) # PyCtxt

# Decrypt and Decode
ptxt_dec = HE.decrypt(int_ctxt)   # PyPtxt
integer_dec = HE.decode(ptxt_dec) # integer

print("2. Encryption & Decryption: ")
print("Encrypting integer: ", integer, " -> ", int_ptxt , " -> ", int_ctxt)
print("Decrypting integer: ", int_ctxt, " -> ", ptxt_dec, " -> ", integer_dec[:3],"...")




# %% --------------------------------------------------
# 3. Homomorphic Operations (Sec. 4.3)
# -----------------------------------------------------
# we will define two integers, encrypt them and operate:
ptxt_a = HE.encode(-12)
ptxt_b = HE.encode(34)
ctxt_a = HE.encrypt(56)
ctxt_b = HE.encrypt(-78)

# ctxt-ctxt operations
ctxt_s = ctxt_a + ctxt_b # or ctxt_a += ctxt_b (in place)
ctxt_m = ctxt_a * ctxt_b

# ctxt-ptxt operations
ctxt_s_p = ptxt_a + ctxt_b # or 12 + ctxt_b
ctxt_m_p = ctxt_a * ptxt_b # or ctxt_a * 34

# maintenance operations
HE.relinKeyGen()        # bfv only
HE.relinearize(ctxt_s)  # requires relinKey
# HE.rescale_to_next(ctxt_r) # ckks only

# rotations (length n)
ctxt_c = HE.encrypt([1,2,3,4])
ctxt_rotated = ctxt_c << 1 # [2,3,4,0,...,0,1


# %% --------------------------------------------------
# 4. IO & Serialization (Sec. 4.4)
# -----------------------------------------------------
import os # to cleanup files

##### CLIENT
HE = Pyfhel()
HE.contextGen(scheme='BFV', n=4096, p_bits=0, p=65537, sec=128)
HE.keyGen() # Generates public and private key
# Save context and public key only
HE.save_public_key("mypk.pk")
HE.save_context("mycontext.con")
# Encrypt and save inputs
ctxt_a = HE.encrypt(15) # implicit encoding
ctxt_b = HE.encrypt(25)
ctxt_a.save("ctxt_a.ctxt")
ctxt_b.save("ctxt_b.ctxt")

##### SERVER
HE_server = Pyfhel()    
HE_server.load_context("mycontext.con")
HE_server.load_public_key("mypk.pk") # no secret key
# Load ciphertexts
ca = PyCtxt(pyfhel=HE_server, fileName="ctxt_a.ctxt")
cb = PyCtxt(pyfhel=HE_server, fileName="ctxt_b.ctxt")
# Compute homomorphically and send result
cr = (ca + cb) * 2
cr.save("cr.ctxt")

##### CLIENT 
# Load and decrypt result
c_res = PyCtxt(pyfhel=HE, fileName="cr.ctxt")
print(c_res.decrypt())
for f in ["mypk.pk", "mycontext.con", "ctxt_a.ctxt", "ctxt_b.ctxt", "cr.ctxt"]:
    os.remove(f)



# %% --------------------------------------------------
# 5. Exploring CKKS pitfalls (Sec. 5.1)
# -----------------------------------------------------
from Pyfhel import PyCtxt, Pyfhel, PyPtxt
HE = Pyfhel()
HE.contextGen(scheme='CKKS', n=16384, qi=[30,30,30,30,30], scale=1)
HE.keyGen()
ctxt_x = HE.encrypt(3.1, scale=2 ** 30) # implicit encode
ctxt_y = HE.encrypt(4.1, scale=2 ** 30)
ctxt_z = HE.encrypt(5.9, scale=2 ** 30)

ctxtSum = HE.add(ctxt_x, ctxt_y)
ctxtProd = HE.multiply_plain(ctxt_z, HE.encode(5))
ctxt_t = HE.multiply(ctxtSum, ctxtProd)

ptxt_ten = HE.encode(10, scale=2 ** 30)
try:
    ctxt_result = HE.add_plain(ctxt_t, ptxt_ten) #error: mismatched scales
except ValueError as e:
    assert str(e) == "scale mismatch"
    print("Mismatched scales detected!")
    
ptxt_d = HE.encode(10, 2 ** 30)
ctxt_d = HE.encrypt(ptxt_d)
HE.rescale_to_next(ctxt_t)  # 2^90 -> 2^60
HE.rescale_to_next(ctxt_t)  # 2^60 -> 2^30

HE.mod_switch_to_next(ctxt_d) # match first rescale
HE.mod_switch_to_next(ctxt_d) # match second rescale

ctxt_t.set_scale(2**30)
ctxt_result = HE.add(ctxt_t, ctxt_d) # final result

# NOTE: The original code (substituting `HE.multiply` and  `HE.add`
#  by `+` and `*`) no longer generates an error: scales are 
#  automatically aligned using HE.align_mod_n_scale when using 
#  operator overloads `+`, `-`, `*` and `/`.


# %% --------------------------------------------------
# 6. Implementing Key-Recovery for CKKS (Sec. 5.2)
# -----------------------------------------------------
# Setup: Encrypt, Decrypt, Decode
ctxt = HE.encrypt(0, scale=2**40)
ptxt_dec = HE.decrypt(ctxt)
values = HE.decodeComplex(ptxt_dec)

# Attack
ptxt_re = HE.encode(values, scale=2**40)
a = HE.poly_from_ciphertext(ctxt,1) # PyPoly
b = HE.poly_from_ciphertext(ctxt,0) # or b = ctxt[0]
m = HE.poly_from_plaintext(ctxt, ptxt_re) # PyPoly
s = (m - b) * ~a # ~a = inverse of a


# sphinx_gallery_thumbnail_path = 'static/thumbnails/helloworld.png'
# %%
