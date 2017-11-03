# Demo on the use of Binary operations (AND, XOR, NOT) using Pyfhel
#    The key is to use p=2 and r=1, and compress directly the numbers
#    in binary format (v1 would be equal to 3 and v2 would be equal to 5)
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
HE = Pyfhel()
KEYGEN_PARAMS={ "p":2,      "r":1,
                "d":1,        "c":2,
                "sec":80,     "w":64,
                "L":10,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("Pyfhel DEMO for binary operations")
print("   Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")

v1 = [0,0,1,1]
v2 = [0,1,0,1]
ones = [1]

ptxt1 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)
pones = PyPtxt(ones, HE)

ctxt1 = HE.encrypt(ptxt1)
ctxt2 = HE.encrypt(ptxt2)
cones = HE.encrypt(pones, fill=1)

print("Encrypted v1: ", v1)
print("Encrypted v2: ", v2)
#XOR operation
ctxt1 += ctxt2      # `ctxt1 = ctxt1 + ctxt2` would also be valid
v3 = HE.decrypt(ctxt1)
print("v1 XOR v2 -> ", v3)

print("v3: ", v3)
print("v2: ", v2)
#AND
ctxt1 *= ctxt2      # `ctxt1 = ctxt1 * ctxt2` would also be valid
v4 = HE.decrypt(ctxt1)
print("v3 AND v2 -> ", v4)

print("v4: ", v4)
#NOT
ctxt1 += cones
v5 = HE.decrypt(ctxt1)
print("NOT v4: ", v5)


v1 = [0,0,1,1]
v2 = [0,1,0,1]
ptxt1 = PyPtxt(v1, HE)
ptxt11 = PyPtxt(v1, HE)
ptxt2 = PyPtxt(v2, HE)

ctxt1 = HE.encrypt(ptxt1)
ctxt11 = HE.encrypt(ptxt11)
ctxt2 = HE.encrypt(ptxt2)
print("Encrypted v1: ", v1)
print("Encrypted v2: ", v2)
# v1 OR v2 = (v1 XOR v2) XOR (v1 AND v2)
ctxt1 += ctxt2
ctxt11 *= ctxt2
ctxt1 += ctxt11
v3 = HE.decrypt(ctxt1)
print("v1 OR v2 -> ", v3)
