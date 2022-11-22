"""
Saving and Restoring
==============================

This demo creates and saves every kind of object managed by Pyfhel.
Subsequently, these objects are loaded and verified.

There are three methods: files, byte-strings or pickling.
"""

import os
import numpy as np
from Pyfhel import Pyfhel, PyPtxt, PyCtxt

# %%
# 1. Create one of each serializable object in Pyfhel
# ------------------------------------------------------
# First we create a Pyfhel object with all types of keys
HE = Pyfhel(context_params={'scheme':'bfv', 'n':2**14, 't_bits':32})
HE.keyGen()
HE.rotateKeyGen()
HE.relinKeyGen()
# Then we encrypt some data
c = HE.encrypt(np.array([42]))
p = HE.encode(np.array([-1]))

print("1. Creating serializable objects")
print(f"  Pyfhel object HE: {HE}")
print(f"  PyCtxt c=HE.encrypt([42]): {c}")
print(f"  PyPtxt p=HE.encode([-1]): {p}")


# %%
# 2. Checking size of objects before serializing
# ------------------------------------------------------
con_size, con_size_zstd   = HE.sizeof_context(),    HE.sizeof_context(compr_mode="zstd")
pk_size,  pk_size_zstd    = HE.sizeof_public_key(), HE.sizeof_public_key(compr_mode="zstd")
sk_size,  sk_size_zstd    = HE.sizeof_secret_key(), HE.sizeof_secret_key(compr_mode="zstd")
rotk_size,rotk_size_zstd  = HE.sizeof_rotate_key(), HE.sizeof_rotate_key(compr_mode="zstd")
rlk_size, rlk_size_zstd   = HE.sizeof_relin_key(),  HE.sizeof_relin_key(compr_mode="zstd")
c_size,   c_size_zstd     = c.sizeof_ciphertext(),  c.sizeof_ciphertext(compr_mode="zstd")
# alternatively, for ciphertext sizes you can use sys.getsizeof(c)

print("2. Checking size of serializable objects (with and without compression)")
print(f"   - context:    [ \"zstd\"  --> {con_size_zstd} | No compression --> {con_size}]")
print(f"   - public_key: [ \"zstd\"  --> {pk_size_zstd} | No compression --> {pk_size}]")
print(f"   - secret_key: [ \"zstd\"  --> {sk_size_zstd} | No compression --> {sk_size}]")
print(f"   - relin_key:  [ \"zstd\"  --> {rotk_size_zstd} | No compression --> {rotk_size}]")
print(f"   - rotate_key: [ \"zstd\"  --> {rlk_size_zstd} | No compression --> {rlk_size}]")
print(f"   - c:          [ \"zstd\"  --> {c_size_zstd} | No compression --> {c_size}]")

# %%
# 3. Save & restore everything into/from files
# ------------------------------------------------
# We will be using a temporary directory for this
import tempfile
tmp_dir = tempfile.TemporaryDirectory()
tmp_dir_name = tmp_dir.name

# Now we save all objects into files
HE.save_context(tmp_dir_name + "/context")
HE.save_public_key(tmp_dir_name + "/pub.key")
HE.save_secret_key(tmp_dir_name + "/sec.key")
HE.save_relin_key(tmp_dir_name + "/relin.key")
HE.save_rotate_key(tmp_dir_name + "/rotate.key")
c.save(tmp_dir_name + "/c.ctxt")
p.save(tmp_dir_name + "/p.ptxt")

print("2a. Saving everything into files. Let's check the temporary dir:")
print("\n\t".join(os.listdir(tmp_dir_name)))

# Now we restore everything and quickly check if it works. 
#  Note! make sure to set the `pyfhel` parameter in PyCtxt/PyPtxt creation!
HE_f = Pyfhel() # Empty creation
HE_f.load_context(tmp_dir_name + "/context")
HE_f.load_public_key(tmp_dir_name + "/pub.key")
HE_f.load_secret_key(tmp_dir_name + "/sec.key")
HE_f.load_relin_key(tmp_dir_name + "/relin.key")
HE_f.load_rotate_key(tmp_dir_name + "/rotate.key")
c_f = PyCtxt(pyfhel=HE_f, fileName=tmp_dir_name + "/c.ctxt")
p_f = PyPtxt(pyfhel=HE_f, fileName=tmp_dir_name + "/p.ptxt", scheme='bfv')

print("2b. Loading everything from files into a new environment.")
# Some checks
assert HE_f.decryptInt(HE_f.encrypt(np.array([42])))[0]==42, "Incorrect encryption"
assert HE_f.decryptInt(c_f)[0]==42, "Incorrect decryption/ciphertext"
assert HE_f.decodeInt(p_f)[0]==-1, "Incorrect decoding"
assert HE_f.decryptInt(c_f >> 1)[1]==42, "Incorrect Rotation"
c_relin = c_f**2
~c_relin
assert c_relin.size()==2, "Incorrect relinearization"
print(" All checks passed! Loaded from files correctly")
# Cleaning up temporary directory
tmp_dir.cleanup()


# %%
# 4. Save everything into byte-strings
# ----------------------------------------
# Now we save all objects into bytestrings
#  This is useful to send objects over the network as payload (See Client/Server demo)
s_context   = HE.to_bytes_context()
s_public_key= HE.to_bytes_public_key()
s_secret_key= HE.to_bytes_secret_key()
s_relin_key = HE.to_bytes_relin_key()
s_rotate_key= HE.to_bytes_rotate_key()
s_c         = c.to_bytes()
s_p         = p.to_bytes()

print("4a. Save all objects into byte-strings")
print(f"   - s_context: {s_context[:10]}...")
print(f"   - s_public_key: {s_public_key[:10]}...")
print(f"   - s_secret_key: {s_secret_key[:10]}...")
print(f"   - s_relin_key: {s_relin_key[:10]}...")
print(f"   - s_rotate_key: {s_rotate_key[:10]}...")
print(f"   - s_c: {s_c[:10]}...")
print(f"   - s_p: {s_p[:10]}...")


# Now we load everything and quickly check if it works. 
HE_b = Pyfhel()                 # Empty creation
HE_b.from_bytes_context(s_context)
HE_b.from_bytes_public_key(s_public_key)
HE_b.from_bytes_secret_key(s_secret_key)
HE_b.from_bytes_relin_key(s_relin_key)
HE_b.from_bytes_rotate_key(s_rotate_key)
c_b = PyCtxt(pyfhel=HE_b, bytestring=s_c)
p_b = PyPtxt(pyfhel=HE_b, bytestring=s_p)
    

print("4b. Loading everything from bytestrings.")
# Some checks
assert HE_b.decryptInt(HE_b.encryptInt(np.array([42], dtype=np.int64)))[0]==42, "Incorrect encryption"
assert HE_b.decryptInt(c_b)[0]==42, "Incorrect decryption/ciphertext"
assert HE_b.decodeInt(p_b)[0]==-1, "Incorrect decoding"
assert HE_b.decryptInt(c_b >> 1)[1]==42, "Incorrect Rotation"
c_relin = c_b**2
~c_relin
assert c_relin.size()==2, "Incorrect relinearization"
print("  All checks passed! Loaded from bytestrings correctly")


# %%
# 5. Pickling Python objects
# -------------------------------
# A last alternative is to pickle the python objects and then unpickle them.
#  > WARNING! when pickling a Pyfhel object only the context is picked inside <
#                (To avoid accidental sharing of the secret key)
# 
#    To share keys, use one of the two methods above (files, bytestrings)

import pickle
pkls_pyfhel = pickle.dumps(HE)   # pickle.dump(HE, file) to dump in a file
pkls_ctxt   = pickle.dumps(c)

print("5a. Pickling Pyfhel & PyCtxt objects.")
print(f"  - pkls_pyfhel: {pkls_pyfhel[:10]}...")
print(f"  - pkls_ctxt: {pkls_ctxt[:10]}...")

# To load the objects, just call `pickle.loads`
HE_pkl = pickle.loads(pkls_pyfhel) # pickle.load(file) to load from file
c_pkl = pickle.loads(pkls_ctxt)
print("5b. Loaded pickled objects")
print(f"   - HE_pkl: {HE_pkl}")
print(f"   - c_pkl: {c_pkl}")

# sphinx_gallery_thumbnail_path = 'static/thumbnails/saveRestore.png'