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

ctxt1 += ctxt2      # `ctxt1 = ctxt1 + ctxt2` would also be valid
v3 = HE.decrypt(ctxt1)
print("add: v1 + v2 -> ", v3)

print("v3: ", v3)
print("v2: ", v2)

ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid
v4 = HE.decrypt(ctxt1)
print("mult: v3 * v2 -> ", v4)
