"""
Client/Server demo with Pyfhel
========================================

Context Parameters shows how several parameters affect performance.
"""
import numpy as np
from Pyfhel import Pyfhel, PyCtxt
from base64 import decodebytes
try:
    from flask import Flask, request
except ImportError:
    print("This demo requires the `flask` python module (install with pip). Exiting.")
    exit(0)

# Server weights -> encode in plaintext
w = np.array([0.5, -1.5,   4,  5])

# Quick setup of the server using flask
app = Flask(__name__)

@app.route('/fhe_mse', methods=['POST'])
def post():
    print("Received Request!")

    # Read all bytestrings
    HE_server = Pyfhel()
    HE_server.from_bytes_context(request.json.get('context').encode('cp437'))
    HE_server.from_bytes_public_key(request.json.get('pk').encode('cp437'))
    HE_server.from_bytes_relin_key(request.json.get('rlk').encode('cp437'))
    HE_server.from_bytes_rotate_key(request.json.get('rtk').encode('cp437'))
    cx = PyCtxt(pyfhel=HE_server, bytestring=request.json.get('cx').encode('cp437'))
    print(f"[Server] received {HE_server=} and {cx=}")

    # Encode weights in plaintext
    ptxt_w = HE_server.encode(w)

    # Compute weighted average
    c_mean = (cx * ptxt_w)
    c_mean /= 4  # 4
    c_mean += (c_mean >> 1)   # cumulative sum
    c_mean += (c_mean >> 2)   # element [3] contains the result
    print(f"[Server] Average computed! Responding: {c_mean=}")

    # Serialize encrypted result and answer it back
    return c_mean.to_bytes().decode('cp437')
  
app.run(host='0.0.0.0', port=5000) # Run, accessible via http://localhost:5000/


# sphinx_gallery_thumbnail_path = 'static/thumbnails/clientServer.png'