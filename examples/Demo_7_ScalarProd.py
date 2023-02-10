"""
Scalar Product.
==============================

This demo shows how to compute scalar product.

To compute the scalar product between two vectors of size l, we will encrypt
each vector into one (if l <= n_slots) or several ciphertexts (l>n), then compute
the SIMD multiplication and cumulative sum (via rotations and sums), to finally
decrypt the result.
"""
#  %%
# ---------------------------------------------------------------------------- #
# A) SCALAR PRODUCT WITH BFV
# ---------------------------------------------------------------------------- #

# %%
# A1. Vector Generation
# ---------------------------
# We will define a pair of 1D integer vectors of size l and elementsize <= ``|v_max|``.
#  For the purpose of this demo, we can study three cases:
#  #1: small l (l <= n) and high v_max.    --> encoding with trailing zeros
#  #2: fitting l (l = n) and medium v_max. --> fits the encoding perfectly
#  #3: large l (l > n) and low v_max.      --> several ciphertexts per vector
#
# @User: You can modify the case selection below
CASE_SELECTOR = 2          # 1, 2 or 3

import warnings
import numpy as np
rng = np.random.default_rng(42)

case_params = {
    1: {'l': 256, 'v_max': 2**24-1},         # small l, high v_max
    2: {'l': 4096, 'v_max': 2**16-1},        # fitting l, medium v_max
    3: {'l': 65536, 'v_max': 2**8-1},        # large l, low v_max
}[CASE_SELECTOR]
l, v_max = case_params['l'], case_params['v_max']

# Generate two random vectors with l elements of values <= |v_max|
v1 = rng.integers(-v_max, v_max, size=l) 
v2 = rng.integers(-v_max, v_max, size=l)
spRes = v1@v2
print("\nA1. Vector generation")
print(f"\tv1 = {str(v1)[:40]+'...'}")
print(f"\tv2 = {str(v2)[:40]+'...'}")
print(f"\tvRes = {spRes}")


# %%
# A2. Context and key setup
# ---------------------------
# Parameter selection goes according to vector length and max element size.
from Pyfhel import Pyfhel

# utilities to generate context parameters 
bitsize                  = lambda x: np.ceil(np.log2(x))
get_closest_power_of_two = lambda x: int(2**(bitsize(x)))

def get_BFV_context_scalar_prod(
    l: int, v_max: int, sec: int=128,
    use_n_min: bool=True
) ->Pyfhel:
    """
    Returns the best context parameters to compute scalar product in BFV scheme.

    The important context parameters to set are:
    - n: the polynomial modulus degree (= n_slots)
    - t: the plaintext modulus         (plaintext element size)

    *Optimal n*: Chosen among {2**10, 2**11, 2**12, 2**13, 2**14, 2**15}, it is
        the closest power of two to the vector length. However, in order to enable 
        relinearization & rotation (which requires at least two qualifying primes),
        the minimum value is:
        - n = 2**12 if sec in {128, 192}
        - n = 2**13 if sec = 256
        The bigger n, the more secure the scheme, but the slower the computations.
        (it might be worth using n<l and have multiple ciphertexts per vector)

        NOTE: the context params are read from seal/utils/globals.cpp, in 
        accordance with homomorphicencryption.org standard to get the chosen 
        security level.

    *Optimal t*: Choose the smallest t (smaller t yields better performance), 
        while being big enough to hold the result of the entire operation:
        --> t_bits = bitxsize(v_max)*2 + bitsize(l)
                              ^      ^           ^
                        max value | mult |  cumul. sum
        There is, however, a minimal size on t_bits for a given `n`:
               t_bits_min = 14     if   n <= 2**11
               t_bits_min = 16     if   n <= 2**12
               t_bits_min = 17     otherwise
    
    Arguments:
        l: vector length
        v_max: max element value
    
    Returns:
        Pyfhel: context to perform homomorphic encryption
    """
    #> OPTIMAL t --> minimum for chosen `n`, or big enough to hold v1@v2
    t_bits_min = 17
    t_bits = max(t_bits_min, (v_max).bit_length()*2 + bitsize(l)) 
    if t_bits > 60:
        raise ValueError(f"t_bits = {t_bits} > 60. Choose a smaller v_max.")

    #> OPTIMAL n
    n_min = 2**12 if sec in [128, 192] else 2**13
    if use_n_min:           n = n_min    # use n_min regardless of l
    elif 2*l < n_min:       n = n_min    # Smallest
    elif 2*l > 2**15:       n = 2**15    # Largest
    else:                   n = get_closest_power_of_two(2*l)

    context_params = {
        'scheme': 'BFV',
        'n': n,          # Poly modulus degree. BFV ptxt is a n//2 by 2 matrix.
        't_bits': t_bits,# Plaintext modulus.
        'sec': sec,      # Security level.
    }

    # Increasing `n` to get enough noise budget for the c1*c2 multiplication.
    #  Since the noise budget in a multiplication consumes t_bits (+...) noise
    #  budget and we start with `total_coeff_modulus_bit_count-t_bits` budget, #  we check if this is high enough to decrypt correctly.
    HE = Pyfhel()
    total_coeff_modulus_bit_count = 0
    while total_coeff_modulus_bit_count - 2*t_bits <= 0:
        context_status = HE.contextGen(**context_params)
        total_coeff_modulus_bit_count = HE.total_coeff_modulus_bit_count
        context_params['n'] *= 2
        if context_params['n'] > 2**15:
            raise ValueError(f"n = {context_params['n']} > 2**15. Valid parameters not found.")
    
    # Increasing t_bits to maintain coprimality between t and q
    while context_status != 'success: valid':
        context_params['t_bits'] += 1
        if context_params['t_bits'] > 60:
            raise ValueError(f"t_bits= {context_params['t_bits']} > 60. Valid parameters not valid.")
        context_status = HE.contextGen(**context_params)
    return HE

# Setup parameters for HE context
HE = get_BFV_context_scalar_prod(l, v_max, sec=128, use_n_min=True)
HE.keyGen()
HE.relinKeyGen()
HE.rotateKeyGen()

print("\nA2. BFV context generation")
print(f"\t{HE}")


# %%
# A3. BFV Encryption
# -----------------------------------------

# Encrypt each vector into one (if l <= n_slots) or several ciphertexts (l>n)
c1 = [HE.encrypt(v1[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]
c2 = [HE.encrypt(v2[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]

print("\nA3. Integer Encryption")
print("->\tv1= ", str(v1)[:40],'...]\n\t--> c1= ', c1)
print("->\tv2= ", str(v2)[:40],'...]\n\t--> c2= ', c2)

# %%
# A4. BFV Scalar Product Evaluation
# -----------------------------------------
# Scalar product requires a multiplication and a cumulative sum of the products.

# If l <= n_slots (one single ciphertext per vector), we can perform the scalar
#  product in one step using the `@` operator (matmul).
if len(c1)==len(c2)==1:
    cRes = c1[0] @ c2[0]
# Otherwise, we should first multiply (and relinearize), then add all ciphertexts,
#  and finally perform the cumulative addition inside the final ciphertext
else:
    cRes = sum([~(c1[i]*c2[i]) for i in range(len(c1))])
    # Cumulative sum
    cRes = HE.cumul_add(cRes)
    


# Lets decrypt and check the result!
res = HE.decrypt(cRes)[0]

print("\nA4. Scalar Product Evaluation")
print("->\tc1@c2= ", cRes)
print("->\tHE.decrypt(c1@c2)= ", res)
print("->\tExpected:   c1@c2= ", spRes)
assert res == spRes, "Incorrect result!"
print("---------------------------------------")


# %%
# ---------------------------------------------------------------------------- #
# B) SCALAR PRODUCT WITH CKKS
# ---------------------------------------------------------------------------- #
# Let's repeat the experiment in CKKS!
# 
# In this case we don't have a noise_level operation to check the current noise,
#  but we can precisely control the maximum # of multiplications by setting qi.

# B1. Vector Generation
# ---------------------------
# CKKS doesn't have the inherent scale limitations of integer-based BFV, so we
#  can use floating-point vectors, and employ a `scale` of up to 60 bits to hold
#  values of that size.
import numpy as np
rng = np.random.default_rng(42)

# We will define a pair of 1D integer vectors of size l.
#  For the purpose of this demo, we can study two cases:
#  #1: small l (l <= n).     --> encoding with trailing zeros
#  #3: large l (l > n).      --> several ciphertexts per vector

# @User: You can modify the case selection below
CASE_SELECTOR = 1          # 1 or 2

case_params = {
    1: {'l': 256},         # small l
    2: {'l': 65536},       # large l
}[CASE_SELECTOR]
l = case_params['l']

# Generate two vectors with l elements drawn from a normal distribution N(0,100)
v1 = rng.normal(loc=0, scale=100, size=l)    # Not bounded!
v2 = rng.normal(loc=0, scale=100, size=l)
spRes = v1@v2
print("\nB1. CKKS Vector generation")
print(f"\tv1 = {str(v1)[:40]+'...'}")
print(f"\tv2 = {str(v2)[:40]+'...'}")
print(f"\tvRes = {spRes}")


# %%
# B2. CKKS Context setup
# ---------------------------
# Parameter selection goes according to vector length only.
from Pyfhel import Pyfhel

def get_CKKS_context_scalar_prod(
    l: int, sec: int=128,
    use_n_min: bool=True
) ->Pyfhel:
    """
    Returns the best context parameters to compute scalar product in CKKS scheme.

    The important context parameters to set are:
    - n: the polynomial modulus degree (= 2*n_slots)

    *Optimal n*: Chosen among {2**12, 2**13, 2**14, 2**15}.
        The bigger n, the more secure the scheme, but the slower the computations.
        It might be faster to use n<l and have multiple ciphertexts pervector.
    
    Arguments:
        l: vector length
        v_max: max element value
    
    Returns:
        Pyfhel: context to perform homomorphic encryption
    """
    #> OPTIMAL n
    n_min =  2**13
    if use_n_min:           n = n_min    # use n_min regardless of l
    elif 2*l < n_min:       n = n_min    # Smallest
    elif 2*l > 2**15:       n = 2**15    # Largest
    else:                   n = get_closest_power_of_two(2*l)

    context_params = {
        'scheme': 'CKKS',
        'n': n,          # Poly modulus degree. BFV ptxt is a n//2 by 2 matrix.
        'sec': sec,      # Security level.
        'scale': 2**20, 
        'qi_sizes': [60, 20, 60],   # Max number of multiplications = 1
    }
    HE = Pyfhel(context_params)
    return HE

# Setup parameters for HE context
HE = get_CKKS_context_scalar_prod(l, sec=128, use_n_min=True)
HE.keyGen()
HE.relinKeyGen()
HE.rotateKeyGen()

print("\nB2. CKKS context generation")
print(f"\t{HE}")


# %%
# B3. ckks Encryption
# -----------------------------------------

# Encrypt each vector into one (if l <= n_slots) or several ciphertexts (l>n)
c1 = [HE.encrypt(v1[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]
c2 = [HE.encrypt(v2[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]

print("\nB3. CKKS Fixed-point Encoding & Encryption")
print("->\tv1= ", str(v1)[:40],'...]\n\t--> c1= ', c1)
print("->\tv2= ", str(v2)[:40],'...]\n\t--> c2= ', c2)

# %%
# B4. CKKS Scalar Product Evaluation
# -----------------------------------------
# We perform the same ops as in the BFV case
if len(c1)==len(c2)==1:
    cRes = c1[0] @ c2[0]
else:
    cRes = [~(c1[i]*c2[i]) for i in range(len(c1))]
    for i in range(1,len(cRes)):
        cRes[0] += cRes[i]
    cRes = HE.cumul_add(cRes[0])


# Lets decrypt and check the result!
res = HE.decrypt(cRes)[0]

print("\nB4. CKKS Scalar Product Evaluation")
print("->\tc1@c2= ", cRes)
print("->\tHE.decrypt(c1@c2)= ", res)
print("->\tCorrect result: ", spRes)
assert np.allclose(res, spRes, rtol=1/1000), "Incorrect result!"
print("---------------------------------------")


# sphinx_gallery_thumbnail_path = 'static/thumbnails/dotproduct.png'
# %%
