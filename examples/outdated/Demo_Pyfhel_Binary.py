# Demo on the use of Binary operations (AND, XOR, NOT) using Pyfhel
#    The key is to use p=2 and r=1, and compress directly the numbers
#    in binary format.

from Pyfhel import Pyfhel, PyPtxt, PyCtxt

print("==============================================================")
print("===================== Pyfhel for BINARY ======================")
print("==============================================================")

print("1. Creating Context and KeyGen in a Pyfhel Object ")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537)  # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_Context.py, and in the docs of
                        #  the function (link to docs in README).
HE.keyGen()             # Key Generation.


print("2. Formatting integers in binary and encrypting them")
# We create a quick function to turn an integer into its binary representation
to_bin = lambda x,n=4: list(map(int,bin(x)[2:].rjust(n,'0')))
integer1 = # [0,0,1,1]
integer2 = # [0,1,0,1]
ones = [1]

# We now encrypt the binary vectors
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
