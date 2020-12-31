"""
Client/Server demo with Pyfhel
========================================

Context Parameters shows how several parameters affect performance.
"""

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
import tempfile
from pathlib import Path

# Using a temporary dir as a "secure channel"
# This can be changed into real communication using other python libraries.
secure_channel = tempfile.TemporaryDirectory()
sec_con = Path(secure_channel.name)
pk_file = sec_con / "mypk.pk"
contx_file = sec_con / "mycontx.con"


##### CLIENT
#HE Object Creation, including the public and private keys
HE = Pyfhel()    
HE.contextGen(p=65537, m=2**12) 
HE.keyGen() # Generates both a public and a private key

# Saving only the public key and the context
HE.savepublicKey(pk_file)
HE.saveContext(contx_file)

# Serializing two float values
a = 1.5
b = 2.5
ca = HE.encryptFrac(a)
cb = HE.encryptFrac(b)

ca.to_file(sec_con / "ca.ctxt")
cb.to_file(sec_con / "cb.ctxt")




##### SEMI-HONEST CLOUD
# Generating a second HE, acting as the honest-but-curious Cloud provider,
#  that will perform the operations and try to decrypt everything
HE_Cl = Pyfhel()    
HE_Cl.restoreContext(contx_file)
HE_Cl.restorepublicKey(pk_file)

# loading the two ciphertexts. There is clearly potential for improvement here
c2a = PyCtxt(pyfhel=HE_Cl, fileName=sec_con / "ca.ctxt", encoding=float)
c2b = PyCtxt(pyfhel=HE_Cl, fileName=sec_con / "cb.ctxt", encoding=float)

# Attempting to decrypt results raises an error (missing secret key)
#> ---------------------------------------------------------------------------
#> RuntimeError                              Traceback (most recent call last)
#> Pyfhel/Pyfhel.pyx in Pyfhel.Pyfhel.Pyfhel.decryptFrac()
#> RuntimeError: Missing a Private Key [...]
try:
    print(HE_Cl.decrypt(c2a))
    raise Exception("This should not be reached!")
except RuntimeError:
    print("The cloud tried to decrypt, but couldn't!")

# The cloud operates with the ciphertexts:
c_mean = (c2a + c2b) / 2

# And sends the result back
c_mean.to_file(sec_con / "c_mean.ctxt")




##### CLIENT
# Load and decrypt Result
c_res = PyCtxt(pyfhel=HE, fileName=sec_con / "c_mean.ctxt", encoding=float)
print(c_res.decrypt())


# Cleaning up secure channel
secure_channel.cleanup()



# sphinx_gallery_thumbnail_path = 'static/thumbnails/clientServer.png'