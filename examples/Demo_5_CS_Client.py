"""
Client/Server demo with Pyfhel
========================================

This demo shows an example of Client-Server interaction, where the client sends
an encrypted vector and the server answers with the weighted average based on his
weights.
"""
# %% 1. Setup Client
import numpy as np
from Pyfhel import Pyfhel, PyCtxt
try:
    import requests
except ImportError:
    print("This demo requires the `requests` python module (install with pip). Exiting.")
    exit(0)

# Generate Pyfhel session
print(f"[Client] Initializing Pyfhel session and data...")
HE_client = Pyfhel(context_params={'scheme':'ckks', 'n':2**13, 'scale':2**30, 'qi':[30]*5})
HE_client.keyGen()             # Generates both a public and a private key
HE_client.relinKeyGen()
HE_client.rotateKeyGen()

# Generate and encrypt data
x = np.array([1.5, 2, 3.3, 4])
cx = HE_client.encrypt(x)

# Serializing data and public context information
s_context    = HE_client.to_bytes_context()
s_public_key = HE_client.to_bytes_public_key()
s_relin_key  = HE_client.to_bytes_relin_key()
s_rotate_key = HE_client.to_bytes_rotate_key()
s_cx         = cx.to_bytes()

print(f"[Client] sending {HE_client=} and {cx=}")


# %% 2. Setup Server

print(f"[Client] launching server (could be launched separately)...")
import subprocess, os
from pathlib import Path
dir = Path(os.path.realpath("__file__")).parent
process = subprocess.Popen(
    ["python", str(dir / "Demo_5bis_CS_Server.py")],
    stderr=subprocess.STDOUT,
)
import time
time.sleep(6)       # Wait for server initialization
print("[Client] server initialized...")

# %% 3. Launch a request to the server and process the response
#  We map the bytes into strings based on https://stackoverflow.com/a/27527728
r = requests.post('http://127.0.0.1:5000/fhe_mse',
    json={
        'context': s_context.decode('cp437'),
        'pk': s_public_key.decode('cp437'),
        'rlk':s_relin_key.decode('cp437'),
        'rtk':s_rotate_key.decode('cp437'),
        'cx': s_cx.decode('cp437'),
    }
)
# Decrypting result
c_res = PyCtxt(pyfhel=HE_client, bytestring=r.text.encode('cp437'))
res = HE_client.decryptFrac(c_res)

# Checking result
w = np.array([0.5, -1.5,   4,  5]) # in the server
expected = np.mean(x*w)
print(f"[Client] Response received! Result is {np.round(res[3], 4)}, should be {expected}")


# %% 4. Stop server
process.kill()

# sphinx_gallery_thumbnail_path = 'static/thumbnails/encrypting.jpg'