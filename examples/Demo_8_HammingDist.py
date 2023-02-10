"""
Hamming Distance.
==============================

This demo shows how to compute the Hamming Distance between two vectors {0,1}*.

We will translate the hamming distance into a scalar product by translating the
XOR op. to the arithmetic domain:

    xor(x,y) = (x-y)^2 =  x + y - 2*(x*y)
    HD(x,y) = sum (x[i] xor y[i]) = sum(x[i]) + sum(y[i]) - 2*sum(x[i]*y[i])

To do so, we will encode both the vectors and their elementwise squared 
cumul_add in independent vectors, compute the scalar product and add the
remaining terms.

As in the scalar product, we encode each vector into one (if l <= n_slots) or 
several ciphertexts (l>n), then compute the SIMD multiplication and cumulative 
sum (via rotations and sums), to finally add the extra terms and decrypt.

We perform this operation in BFV to get the exact result. CKKS could also be
used, but the result would be an approximation.
"""
#  %%
# ---------------------------------------------------------------------------- #
# HAMMING DISTANCE WITH BFV
# ---------------------------------------------------------------------------- #

# %%
# 1. Vector Generation
# ---------------------------
# We will define a pair of 1D integer vectors of size l in {0,1}*.
#  For the purpose of this demo, we will focus on the case #1 of ScalarProd:
#  #1: small l (l <= n) and high v_max.    --> encoding with trailing zeros
#
# Users can modify l.

import warnings
import numpy as np
rng = np.random.default_rng(42)

l = 256

# Generate two random vectors with l elements of values <= |v_max|
v1 = rng.integers(0, 2, size=l) 
v2 = rng.integers(0, 2, size=l)
hdRes = np.sum(v1^v2)
print("\nA1. Vector generation")
print(f"\tv1 = {str(v1)[:40]+'...'}")
print(f"\tv2 = {str(v2)[:40]+'...'}")
print(f"\tvRes = {hdRes}")


# %%
# 2. Hamming Distance setup
# ---------------------------
# Parameter selection goes according to vector length and max element size.
from Pyfhel import Pyfhel

# utilities to generate context parameters 
bitsize                  = lambda x: np.ceil(np.log2(x))
get_closest_power_of_two = lambda x: int(2**(bitsize(x)))

def get_BFV_context_hammingDist(
    l: int, sec: int=128,
    use_n_min: bool=True
) ->Pyfhel:
    """
    Returns the best context parameters to compute hamming dist. in BFV scheme.

    The important context parameters to set are:
    - n: the polynomial modulus degree (= n_slots)
    - t: the plaintext modulus         (plaintext element size)

    *Optimal n*: Chosen among {2**12, 2**13, 2**14, 2**15}. The min value is:
        - n = 2**12 if sec in {128, 192}
        - n = 2**13 if sec = 256
        The bigger n, the more secure the scheme, but the slower the 
        computations. (it might be worth using n<l and have multiple 
        ciphertexts per vector)

        NOTE: the context params are read from seal/utils/globals.cpp, in 
        accordance with homomorphicencryption.org standard to get the chosen 
        security level.

    *Optimal t*: Choose the smallest t (smaller t yields better performance), 
        while being big enough to hold the result of the entire operation:
        --> t_bits =    2 * bitsize(l)
                        ^           ^
                    square  |  cumul. sum
        There is, however, a minimal size on t_bits for a given `n`:
               t_bits_min = 14     if   n <= 2**11
               t_bits_min = 16     if   n <= 2**12
               t_bits_min = 17     otherwise
    
    Arguments:
        l: vector length
    
    Returns:
        Pyfhel: context to perform homomorphic encryption
    """
    #> OPTIMAL t --> minimum for chosen `n`, or big enough to hold v1@v2
    t_bits_min = 17
    t_bits = max(t_bits_min, 2*bitsize(l))
    if t_bits > 60:
        raise ValueError(f"t_bits = {t_bits} > 60.")

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
        # if (context_status != "success"):
        #     warnings.warn(f"  n={context_params['n']} Doesn't produce valid parameters. Trying 2*n")
        context_params['n'] *= 2
        if context_params['n'] > 2**15:
            raise ValueError(f"n = {context_params['n']} > 2**15. Parameters are not valid.")
    return HE

# Setup parameters for HE context
HE = get_BFV_context_hammingDist(l, sec=128, use_n_min=True)
HE.keyGen()
HE.relinKeyGen()
HE.rotateKeyGen()

print("\n2. BFV context generation")
print(f"\t{HE}")


# %%
# 3. BFV Encryption
# -----------------------------------------

# Encrypt each vector into one (if l <= n_slots) or several ciphertexts (l>n)
c1 = [HE.encrypt(v1[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]
c2 = [HE.encrypt(v2[j:j+HE.get_nSlots()]) for j in range(0,l,HE.get_nSlots())]

sumx = np.expand_dims(np.sum(v1),0)
sumy = np.expand_dims(np.sum(v2),0)
c1_sumx = HE.encrypt(sumx)
c2_sumy = HE.encrypt(sumy)

print("\n3. Boolean Encryption as integers")
print("->\tv1= ", str(v1)[:40],'...]\n\t--> c1= ', c1)
print("->\tv2= ", str(v2)[:40],'...]\n\t--> c2= ', c2)
print("->\tsumx= ", str(sumx),'\n\t--> c1_sumx= ', c1_sumx)
print("->\tsumy= ", str(sumy),'\n\t--> c2_sumy= ', c2_sumy)

# %%
# 4. BFV Hamming Distance Evaluation
# -----------------------------------------
# Evaluate the scalar product, then add the independent terms
c_sp = HE.cumul_add(sum([~(c1[i]*c2[i]) for i in range(len(c1))]))
    
# Hamming Distance
c_hd = c1_sumx + c2_sumy - (c_sp*2)

# Lets decrypt and check the result!
res = HE.decrypt(c_hd)[0]

print("\n4. Hamming Distance Evaluation")
print("->\tHamming(c1, c2)= ", c_hd)
print("->\tHE.decrypt(c1@c2)= ", res)
print("->\tExpected:   v1@v2= ", hdRes)
assert res == hdRes, "Incorrect result!"
print("---------------------------------------")



# sphinx_gallery_thumbnail_path = 'static/thumbnails/hammingDist.png'
# %%
