from Pyfhel import Pyfhel, PyPtxt, PyCtxt

HE = Pyfhel()           # Creating empty Pyfhel object
HE.contextGen(scheme='BFV', n=4096 , p=1024, sec=128)  # Generating context. The p defines the plaintext modulo.
                        #  There are many configurable parameters on this step
                        #  More info in Demo_ContextParameters, and
                        #  in Pyfhel.contextGen()
HE.keyGen()             # Key Generation: generates a pair of public/secret keys
print("1. Setup: ", HE)