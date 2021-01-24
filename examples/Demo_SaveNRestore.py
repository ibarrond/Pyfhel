"""
Saving and Restoring
==============================

This demo creates and saves every kind of object managed by Pyfhel.
Subsequently, these objects are read from the files and verified.

There are two methods: files and serialized (bytes strings, pickling)
"""

import tempfile
import numpy as np

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("=================== Pyfhel SaveRestore FILES =================")
print("==============================================================")


print("1. Creating Context and all possible keys")
HE = Pyfhel()
HE.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
HE.keyGen()
HE.rotateKeyGen(60)
HE.relinKeyGen(60, 4)


print("2. Save all keys into temporary strings")
tmp_dir = tempfile.TemporaryDirectory()
HE.saveContext(tmp_dir.name + "/context")
HE.savepublicKey(tmp_dir.name + "/pub.key")
HE.savesecretKey(tmp_dir.name + "/sec.key")
HE.saverelinKey(tmp_dir.name + "/relin.key")
HE.saverotateKey(tmp_dir.name + "/rotate.key")

print("3. Restore all keys")
HE2 = Pyfhel()
HE2.restoreContext(tmp_dir.name + "/context")
HE2.restorepublicKey(tmp_dir.name + "/pub.key")
HE2.restoresecretKey(tmp_dir.name + "/sec.key")
HE2.restorerelinKey(tmp_dir.name + "/relin.key")
HE2.restorerotateKey(tmp_dir.name + "/rotate.key")


print("4. Testing encryption decryption:")
ctxt1 = HE.encryptBatch([42])
assert HE2.decryptBatch(ctxt1)[0]==42, "decrypting with restored keys should work"
HE2.rotate(ctxt1, -1)
assert HE2.decryptBatch(ctxt1)[1]==42, "decrypting with restored keys should work"
#TODO: show serialization and Pickling

print("5. Testing ciphertext storing:")
ctxt2 = HE.encryptInt(42)
ctxt2.save(tmp_dir.name + "/ctxt2")

ctxt_restored = PyCtxt()
ctxt_restored.load(tmp_dir.name + "/ctxt2", int)
assert HE2.decryptInt(ctxt_restored)==42, "decrypting ciphertext should work"


# Cleaning up secure channel
tmp_dir.cleanup()





print("==============================================================")
print("========== Pyfhel SaveRestore PICKLE & SERIALIZED ============")
print("==============================================================")

print("1. Creating Context and all possible keys, as well as ciphertexts.")
HE = Pyfhel()
HE.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
HE.keyGen()
HE.rotateKeyGen(60)
HE.relinKeyGen(60, 4)
ctxt_int = HE.encryptInt(-12)
ctxt_frac = HE.encryptFrac(-3.754)
ctxt_batch = HE.encryptBatch([-12,5,4,3])
ctxt_list = [HE.encryptFrac(-3.754),  HE.encryptFrac(26.94)]
ctxt_arr = np.array([HE.encryptFrac(-3.754),  HE.encryptFrac(26.94)])

print("2.1 Save all keys into serialized strings")
context_serialized = HE.to_bytes_context()
pubkey_serialized = HE.to_bytes_publicKey()
seckey_serialized = HE.to_bytes_secretKey()
relinkey_serialized = HE.to_bytes_relinKey()
rotkey_serialized = HE.to_bytes_rotateKey()

print("2.2 Pickle all Pyfhel classes into pickled strings")
import pickle
# IMPORTANT! For security reasons,  when pickling a Pyfhel object only the context is picked inside.
# All keys must be serialized and transmitted independently.
pkl_int = pickle.dumps(ctxt_int)      # To serialize the contents only: ser_int = ctxt_int.to_bytes()
pkl_frac = pickle.dumps(ctxt_frac)    # To serialize the contents only: ser_frac = ctxt_frac.to_bytes()
pkl_batch = pickle.dumps(ctxt_batch)  # To serialize the contents only: ser_batch = ctxt_batch.to_bytes()
pkl_list = pickle.dumps(ctxt_list)  
pkl_arr = pickle.dumps(ctxt_arr)

# IMPORTANT! For security reasons,  when pickling a Pyfhel object only the context is picked inside.
# All keys must be serialized and transmitted independently.
pkl_pyfhel = pickle.dumps(HE) 


## NETWORK! Time to send the strings as payload over the

print("3.1 Restore all Pyfhel classes from pickled strings")
HE2 = pickle.loads(pkl_pyfhel)
ctxt_int = pickle.loads(pkl_int)    # To unserialize the contents only: ctxt_int = PyCtxt(serialized=ser_int, encoding=int)
ctxt_frac = pickle.loads(pkl_frac)  # To unserialize the contents only: ctxt_frac = PyCtxt(serialized=ser_frac, encoding=float)
ctxt_batch = pickle.loads(pkl_batch)# To unserialize the contents only: ctxt_batch = PyCtxt(serialized=ser_batch, encoding=list)
ctxt_list = pickle.loads(pkl_list)
ctxt_arr = pickle.loads(pkl_arr)

print("3.2 Restore all keys from serialized strings")
HE2.from_bytes_context(context_serialized)
HE2.from_bytes_publicKey(pubkey_serialized)
HE2.from_bytes_secretKey(seckey_serialized)
HE2.from_bytes_relinKey(relinkey_serialized)
HE2.from_bytes_rotateKey(rotkey_serialized)

print("4. Testing encryption decryption:")
ctxt1 = HE.encryptBatch([42])
assert HE2.decryptBatch(ctxt1)[0]==42, "decrypting with restored keys should work"
HE2.rotate(ctxt1, -1)
assert HE2.decryptBatch(ctxt1)[1]==42, "decrypting with restored keys should work"




print("Everything is correct!")



# sphinx_gallery_thumbnail_path = 'static/thumbnails/saveRestore.png'