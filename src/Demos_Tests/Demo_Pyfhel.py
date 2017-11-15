"""Import all the packages useful for the Demo.
#-Pyfhel is useful to generate keys, encrypt and decrypt.
#-PyPtxt is useful to tranform the input vectors into plain text objects that could be encrypted.
#-PyCtxt is useful to tranform the plain text object in PyCtxt object that are encrypted. PyCtxt can be add, multiply etc with homeomorphic operations."""
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt

print("Pyfhel DEMO")

#Instantiate a Pyfhel object called HE.
HE = Pyfhel()
#Create the Key Generator parameters.
KEYGEN_PARAMS={ "p":257,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

"""Print the Key Generator parameters to let the user knows how his vectors will be encrypted."""
print("   Running KeyGen with params:")
print(KEYGEN_PARAMS)

"""Generate the keys that will be use to encrypted the vectors. The generation of the keys uses the Key Generator parameters. Then print a message to inform the user that the key generation has been completed."""
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")

"""Define two vectors that we will use for the tests."""
v1 = [1,2,3,4,5]
v2 = [2,2,2,2,2]


"""We will first transform these two vectors in plaintext that could be encrypted, then we'll tranform the plain text of these two vectors in homeomorphic encrypted vector. Then we will add and multiply these two encrypted vectors in an homeomorphic way. Finally, we will decrypted the result of the addition and multiplication of the two encrypted vectors and we verify the result is the same that the addition or multiplication of the two vectors without encryption."""


"""Tranform the two vectors in plaintext that are objects that could be encrypted."""
ptxt1 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)

"""Encrypted the two plaintexts to have two Cypher text that are encrypted in an homeomorphic way with the key that have been generated before."""
ctxt1 = HE.encrypt(ptxt1, fill=1)
ctxt2 = HE.encrypt(ptxt2, fill=1)

print("Encrypted v1: ", v1)
print("Encrypted v2: ", v2)


"""Perform homeomorphic operations on the encrypted vectors."""

"""Perform homeomorphic addition"""
ctxt1 += ctxt2  # `ctxt1 = ctxt1 + ctxt2` would also be valid->No because of a  bug in add function! Has to be corrected!
"""Decrypt the result of the addition of the two encrypted vectors"""
v3 = HE.decrypt(ctxt1)
"""The user can then verify if the result of the addition of the two encrypted vectors is the same that the addition of the two vectors without encryption."""
print("Decrypted result of the addition between encrypted v1 and encrypted v2: Decrypt(encrypt(v1) + encrypt(v2)) -> ", v3)
print("Result of the addition between v1 and v2: v1 + v2 ->", map(sum, izip(a,b)))



print("v3: ", v3)
print("v2: ", v2)

ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid->No because of a bug in mult function! Has to be corrected!
v4 = HE.decrypt(ctxt1)
print("mult: v3 * v2 -> ", v4)

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
