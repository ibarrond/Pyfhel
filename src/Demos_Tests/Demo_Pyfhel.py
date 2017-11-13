from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
HE = Pyfhel()
KEYGEN_PARAMS={ "p":257,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("Pyfhel DEMO")
print("   Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")

v1 = [1,2,3,4,5]
v2 = [2,2,2,2,2]

ptxt1 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)

ctxt1 = HE.encrypt(ptxt1, fill=1)
ctxt2 = HE.encrypt(ptxt2, fill=1)

print("Encrypted v1: ", v1)
print("Encrypted v2: ", v2)

ctxt1 += ctxt2  # `ctxt1 = ctxt1 + ctxt2` would also be valid->No because of a  bug in add function! Has to be corrected!
v3 = HE.decrypt(ctxt1)
print("add: v1 + v2 -> ", v3)

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

ctxt1.polynomialMult(ctxt1, coeff)
print("success_Polynomial")
ctxt1polynomial = ctxt1.polynomialMult(ctxt1, coeff)
result = HE.decrypt(ctxt1polynomial)
print("Polynomial result: ", result)
