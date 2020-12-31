"""
Fractionals with Pyfhel
========================================


Fractional / float Demo for Pyfhel, operating with fixed point encoded
values. It follows the same structure as the HelloWorld with Integer encoding.
"""


from Pyfhel import Pyfhel, PyPtxt, PyCtxt


print("1. Creating Context and KeyGen in a Pyfhel Object. Using 64 ")
print("     bits for integer part and 32 bits for decimal part.")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537, base=2, intDigits=64, fracDigits = 32) 
                        # Generating context. The value of p is important.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters.py, and
                        #  in the docs of the function (link to docs in README)
HE.keyGen()             # Key Generation.
print(HE)

print("2. Encrypting Fractionals")
float1 = -7.3
float2 = 3.4
ctxt1 = HE.encryptFrac(float1) # Encryption makes use of the public key
ctxt2 = HE.encryptFrac(float2) # For integers, encryptInt function is used.
print("    int ",float1,'-> ctxt1 ', ctxt1)
print("    int ",float2,'-> ctxt2 ', ctxt2)



print("3. Operating with encrypted fractionals")
ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation
ctxtMul = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation
print(ctxtSum)
print(ctxtSub)
print(ctxtMul)

print("4. Decrypting result:")
resSum = HE.decryptFrac(ctxtSum) # Decryption must use the corresponding function
                                #  decryptInt.
resSub = HE.decryptFrac(ctxtSub) 
resMul = HE.decryptFrac(ctxtMul)
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)

print("NOTE: Very accurate! Let's try lowering the fracDigits from the context.")
print("==============================================================")

print("1bis. Creating Context and KeyGen in a Pyfhel Object. Using 64 ")
print("     bits for integer part and 3 bits for decimal part.")
HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(p=65537, base=2, intDigits=64, fracDigits = 3)
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters.py, and
                        #  in the docs of the function (link to docs in README)
HE.keyGen()             # Key Generation.

print("2bis. Encrypting Fractionals")
float1 = -7.3
float2 = 3.4
ctxt1 = HE.encryptFrac(float1) # Encryption makes use of the public key
ctxt2 = HE.encryptFrac(float2) # For integers, encryptInt function is used.
print("    int ",float1,'-> ctxt1 ', type(ctxt1))
print("    int ",float2,'-> ctxt2 ', type(ctxt2))



print("3bis. Operating with encrypted fractionals")
ctxtSum = ctxt1 + ctxt2         # `ctxt1 += ctxt2` for quicker inplace operation
ctxtSub = ctxt1 - ctxt2         # `ctxt1 -= ctxt2` for quicker inplace operation
ctxtMul = ctxt1 * ctxt2         # `ctxt1 *= ctxt2` for quicker inplace operation


print("4bis. Decrypting result:")
resSum = HE.decryptFrac(ctxtSum) # Decryption must use the corresponding function
                                #  decryptInt.
resSub = HE.decryptFrac(ctxtSub) 
resMul = HE.decryptFrac(ctxtMul)
print("     addition:       decrypt(ctxt1 + ctxt2) =  ", resSum)
print("     substraction:   decrypt(ctxt1 - ctxt2) =  ", resSub)
print("     multiplication: decrypt(ctxt1 + ctxt2) =  ", resMul)

print("NOTE: As you can see, the accuracy drops! As usual, there is a tradeoff.")


# sphinx_gallery_thumbnail_path = 'static/thumbnails/float.png'