
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("========================= Pyfhel DEMO ========================")
print("==============================================================")


print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537)  # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_Context.py, and in the docs of
                        #  the function (link to docs in README).
HE.keyGen()             # Key Generation.


print("2. Encrypting integers 127 and -2")
integer1 = 127
integer2 = -2
ctxt1 = HE.encryptInt(integer1) # Encryption makes use of the public key
ctxt2 = HE.encryptInt(integer2) # For integers, encryptInt function is used.

print("    int ",integer1,'->', type(ctxt1))
print("    int ",integer2,'->', type(ctxt2))

print("3. Operating with encrypted integers")
ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation


print("add: v1 + v2 -> ", v3)

print("v3: ", v3)
print("v2: ", v2)

ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid
v4 = HE.decrypt(ctxt1)
print("mult: v3 * v2 -> ", v4)
