"""
Saving and Restoring
==============================

This demo creates and saves in files every kind of object managed by Pyfhel.
Subsequently, these objects are read from the files and verified.
"""
# sphinx_gallery_thumbnail_path = 'static/thumbnails/saveRestore.png'



import tempfile

from Pyfhel import Pyfhel, PyPtxt, PyCtxt
# Pyfhel class contains most of the functions.
# PyPtxt is the plaintext class
# PyCtxt is the ciphertext class


print("==============================================================")
print("===================== Pyfhel SaveRestore =====================")
print("==============================================================")


print("1. Creating Context and all possible keys")
HE = Pyfhel()
HE.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
HE.keyGen()
HE.rotateKeyGen(60)
HE.relinKeyGen(60, 4)


print("2. Save all keys into temporary directory")
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


print("5. Testing ciphertext storing:")
ctxt2 = HE.encryptInt(42)
ctxt2.save(tmp_dir.name + "/ctxt2")

ctxt_restored = PyCtxt()
ctxt_restored.load(tmp_dir.name + "/ctxt2", int)
assert HE2.decryptInt(ctxt_restored)==42, "decrypting ciphertext should work"


# Cleaning up secure channel
tmp_dir.cleanup()