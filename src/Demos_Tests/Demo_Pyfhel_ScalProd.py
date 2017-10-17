from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
HE = Pyfhel()
KEYGEN_PARAMS={ "p":2,        "r":54,
                "d":0,        "c":3,
                "sec":128,    "w":64,
                "L":16,       "m":-1,
                "R":3,        "s":0,
                "gens":[],    "ords":[]}

print("Pyfhel DEMO")
print("  Running KeyGen with params:")
print(KEYGEN_PARAMS)
HE.keyGen(KEYGEN_PARAMS)
print("  KeyGen completed")
v1 = [range(8), range(3)]
v2 = [range(1,9), range(1,4)]
v3 = [range(8), range(3)]
v4 = [range(8), range(3)]

p1 = PyPtxt(v1, HE)
p2 = PyPtxt(v2, HE)
p3 = PyPtxt(v3, HE)
p4 = PyPtxt(v4, HE)


print("Encryting v1: ", v1)
c1 = HE.encrypt(p1)
print("Encryting v2: ", v2)
c2 = HE.encrypt(p2)
print("Encryting v3: ", v3)
c3 = HE.encrypt(p3)
print("Encryting v4: ", v4)
c4 = HE.encrypt(p4)


c1 += c4
c2 *= c4
c3 %= c4

r1 = HE.decrypt(c1)
r2 = HE.decrypt(c2)
r3 = HE.decrypt(c3)

print("Encrypted sum v1 + v4: ", r1)
print("Encrypted mult v2 * v4: ", r2)
print("Encrypted scalar prod v3 * v4: ", r3)

