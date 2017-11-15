"""Import all the packages useful for the Demo.
#-Pyfhel is useful to generate keys, encrypt and decrypt.
#-PyPtxt is useful to tranform the input vectors into plain text objects that could be encrypted.
#-PyCtxt is useful to tranform the plain text object in PyCtxt object that are encrypted. PyCtxt can be add, multiply etc with homeomorphic operations."""
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt

#Other import useful for the demo.
from itertools import izip
import itertools

print("\n")
print("     ************Pyfhel DEMO************")
print("\n")

"""Define two vectors that we will use for the tests."""
v1 = [1,2,3,4,5]
v2 = [2,2,2,2,2]

print("******Definition of the vectors used during the tests.******")
print("v1: ", v1)
print("v2: ", v2)

print("\n")


#Instantiate a Pyfhel object called HE.
HE = Pyfhel()

print("******Generation of the keys for encryption******")

#Create the Key Generator parameters.
KEYGEN_PARAMS={ "p":257,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

"""Print the Key Generator parameters to let the user knows how his vectors will be encrypted."""
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)

"""Generate the keys that will be use to encrypted the vectors. The generation of the keys uses the Key Generator parameters. Then print a message to inform the user that the key generation has been completed."""
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")

print("\n")

"""We will first transform these two vectors in plaintext that could be encrypted, then we'll tranform the plain text of these two vectors in homeomorphic encrypted vector. Then we will add and multiply these two encrypted vectors in an homeomorphic way. Finally, we will decrypted the result of the addition and multiplication of the two encrypted vectors and we verify the result is the same that the addition or multiplication of the two vectors without encryption."""

print("******Homeomorphic encryption of the two vectors used during the tests******")

"""Tranform the two vectors in plaintext that are objects that could be encrypted."""
ptxt1 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)

"""Encrypted the two plaintexts to have two Cypher text that are encrypted in an homeomorphic way with the key that have been generated before."""
ctxt1 = HE.encrypt(ptxt1, fill=1)
ctxt2 = HE.encrypt(ptxt2, fill=1)

print("Encryption of v1...")
print("Encryption of v2...")

print("Encrypted v1: Encrypt(", v1, ")")
print("Encrypted v2: Encrypt(", v2, ")")

print("\n")

"""Perform homeomorphic operations on the encrypted vectors."""
print("******Test of the homeomorphic operations******")

print("\n")

"""Perform homeomorphic addition"""
print("***Test of the homeomorphic addition***")
print("Encrypted v1: Encrypt(", v1, ")")
print("Encrypted v2: Encrypt(", v2, ")")
print("Performing Encrypt(v1) + Encrypt(v2)...")
ctxt1 += ctxt2  # `ctxt1 = ctxt1 + ctxt2` would also be valid->No because of a  bug in add function! Has to be corrected!
"""Decrypt the result of the addition of the two encrypted vectors"""
v3 = HE.decrypt(ctxt1)
"""v3 is a list of list ie [[a, b, c,...]], so we want to flatten it to obtain [a, b, c,...]"""
v3 = list(itertools.chain.from_iterable(v3))
"""The user can then verify if the result of the addition of the two encrypted vectors is the same that the addition of the two vectors without encryption."""
print("Decrypt(encrypt(v1) + encrypt(v2)) -> ", v3)
v1Plusv2=map(sum, izip(v1,v2))
print("v1 + v2 ->", v1Plusv2)
"""If Decrypt(encrypt(v1) + encrypt(v2)) equal to v1 + v2, The homeomorphic operation works and so it is a success. Else, it is a fail."""
if v3==v1Plusv2:
   print("Homeomorphic operation add is a success: Decrypt(encrypt(v1) + encrypt(v2)) equal to v1 + v2.")
else:
   print("Homeomorphic operation add is a fail: Decrypt(encrypt(v1) + encrypt(v2)) not equal to v1 + v2.")

print("\n")

"""Perform homeomorphic multiplication"""
print("***Test of the homeomorphic multiplication***")
print("Encrypted v3: Encrypt(", v3, ")")
print("Encrypted v2: Encrypt(", v2, ")")
"""ctxt1 contains Encrypt(v3) ie Encrypt(v1) + Encrypt(v2). ctxt2 contains Encrypt(v2). So we perform: Encrypt(v3)*Encrypt(v2)"""
print("Performing Encrypt(v3) * Encrypt(v2)...")
ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid->No because of a bug in mult function! Has to be corrected!
"""Decrypt the result of the multiplication of the two encrypted vectors"""
v4 = HE.decrypt(ctxt1)
"""v4 is a list of list ie [[a, b, c,...]], so we want to flatten it to obtain [a, b, c,...]"""
v4 = list(itertools.chain.from_iterable(v4))
print("Decrypt(encrypt(v3) * encrypt(v2)) -> ", v4)
v3Multv2= [a*b for a,b in izip(v3,v2)]
print("v3 * v2 ->", v3Multv2)
"""If Decrypt(encrypt(v1) + encrypt(v2)) equal to v1 + v2, The homeomorphic operation works and so it is a success. Else, it is a fail."""
if v4==v3Multv2:
   print("Homeomorphic operation mult is a success: Decrypt(encrypt(v3) * encrypt(v2)) equal to v3 * v2.")
else:
   print("Homeomorphic operation mult is a fail: Decrypt(encrypt(v3) + encrypt(v2)) not equal to v3 * v2.")



print("------------------TEST REMY1----------------------")

a0 = [3,3,3,3,3]
a1 = [5,5,5,5,5]
a2 = [2,2,2,2,2]
a3 = [4,4,4,4,4]

pltxt1 = PyPtxt(a0, HE)
pltxt2 = PyPtxt(a1, HE)
pltxt3 = PyPtxt(a2, HE)
pltxt4 = PyPtxt(a3, HE)

cytxt1 = HE.encrypt(pltxt1, fill=1)
cytxt2 = HE.encrypt(pltxt2, fill=1)
cytxt3 = HE.encrypt(pltxt3, fill=1)
cytxt4 = HE.encrypt(pltxt4, fill=1)

coeff = [cytxt1, cytxt2, cytxt3, cytxt4]

ctxt1polynomial = ctxt1.polynomialMult(ctxt1, coeff)
result = HE.decrypt(ctxt1polynomial)
print("Polynomial result: ", result)
