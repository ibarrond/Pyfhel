#   --------------------------------------------------------------------
#   Pyfhel.pyx
#   Author: Alberto Ibarrondo
#   Date: 17/07/2018
#   --------------------------------------------------------------------
#   License: GNU GPL v3
#
#   Pyfhel is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Pyfhel is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#   --------------------------------------------------------------------
"""PYFHEL, PYthon For Homomorphic Encryption Libraries.

Encrypted addition, multiplication, substraction, exponentiation of 
integers/doubles. Implementation of homomorphic encryption using 
SEAL/PALISADE/HELIB as backend. Pyfhel works with PyPtxt as plaintext 
class and PyCtxt as cyphertext class.

Example:
    >>> he = Pyfhel()
    >>> he.ContextGen(p=65537)
    >>> he.KeyGen(p=65537)
    >>> p1 = he.encode(4)
    >>> p2 = he.encode(2)
    >>> c1 = he.encrypt(p1)
    >>> c2 = he.encrypt(p2)
    >>> c1 = c1 + c2
    >>> p_res = he.decrypt(c1)
    6
"""    

# -------------------------------- IMPORTS ------------------------------------
# Both numpy and the Cython declarations for numpy
import numpy as np

# Type checking for only numeric values
from numbers import Number

# Dereferencing pointers in Cython in a secure way
from cython.operator cimport dereference as deref

# Encoding types: 1-UNDEFINED, 2-INTEGER, 3-FRACTIONAL, 4-BATCH
from util import ENCODING_T

# Define Plaintext types
PLAINTEXT_T = (PyPtxt, float, int, np.ndarray)

# ------------------------- PYTHON IMPLEMENTATION -----------------------------
cdef class Pyfhel:

    def __cinit__(self):
        self.afseal = new Afseal()
    def __dealloc__(self):
        if self.afseal != NULL:
            del self.afseal

    
    # ----------------------------- CRYPTOGRAPHY ------------------------------
    cpdef void ContextGen(self, long p, long m=2048, bool flagBatching=False,
                  long base=2, long sec=128, int intDigits=64, int fracDigits = 32):
        """Generates Homomorphic Encryption context based on parameters.
        
        Args:
            p (long): Plaintext modulus. All operations are modulo p.
            m (long=2048): Coefficient modulus. Higher allows more encrypted operations.
                      In batch mode it is the number of integers per ciphertext.
            flagBatching (bool=false): Set to true to enable batching.
            base (long=2): Polynomial base. Affects size of plaintexts/ciphertexts. 
            sec (long=128): Security level equivalent in AES. Either 128 or 192.
            intDigits (int=64): when encrypting/encoding double, truncated positions
                      dedicated to integer part, out of 'm' positions
            fracDigits (int=32): when encrypting/encoding double, truncated positions
                      dedicated to fractional part, out of 'm' positions
                      
        Return:
            None
        """
        self.afseal.ContextGen(p, m, flagBatching, base, sec,intDigits, fracDigits)
        
        
    cpdef void KeyGen(self):
        """Generates a pair of Private/Public Keys.
        
        Based on the current context, initializes one public and one private key. 
        Args:
            None
                      
        Return:
            None
        """
        self.afseal.KeyGen()
    
    # ENCRYPTION encrypt a PyPtxt object into a PyCtxt object
    cpdef PyCtxt encryptInt(self, int64_t value, PyCtxt ctxt=None):
        """Encrypts a single value into a PyCtxt ciphertext.
        
        Encrypts a single value using the current private key, based on the current context.
        Plaintext must either be an integer (int64_t) or a decimal that will get
        truncated (float).
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (int|float): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(value, deref(ctxt._ptr_ctxt))
        ctxt._encoding = ENCODING_T.INTEGER
        return ctxt
    
    cpdef PyCtxt encryptFrac(self, double value, PyCtxt ctxt=None):
        """Encrypts a single value into a PyCtxt ciphertext.
        
        Encrypts a single value using the current private key, based on the current context.
        Plaintext must either be an integer (int64_t) or a decimal that will get
        truncated (float).
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (int|float): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(value, deref(ctxt._ptr_ctxt))
        ctxt._encoding = ENCODING_T.FRACTIONAL
        return ctxt
    
    cpdef PyCtxt encryptBatch(self, vector[int64_t] vec, PyCtxt ctxt=None): 
        """Encrypts a 1D numpy vector of integers into a PyCtxt ciphertext.
        
        Encrypts a 1D numpy vector of integers using the current private key,
        based on the current context. Plaintext must be a 1D numpy vector of integers.
        Requires batch mode. The vector needs to be in 'contiguous' or 'c' mode.
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (np.ndarray[int, ndim=1, mode="c"]): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
        """
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(vec, deref(ctxt._ptr_ctxt)) 
        ctxt._encoding = ENCODING_T.BATCH
        return ctxt  
        
    cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt=None):
        """Encrypts an already encoded PyPtxt plaintext into a PyCtxt ciphertext.
        
        Encrypts an already encoded PyPtxt plaintext using the current private key,
        based on the current context. Plaintext must be a PyPtxt.
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (PyPtxt): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """
        if (ptxt._ptr_ptxt == NULL):
            raise TypeError("Plaintext is empty")
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(deref(ptxt._ptr_ptxt), deref(ctxt._ptr_ctxt)) 
        ctxt._encoding = ptxt._encoding
        return ctxt

    def encrypt(self, ptxt not None, ctxt=None):
        """Encrypts any valid plaintext into a PyCtxt ciphertext.
        
        Encrypts a plaintext using the current private key, based on the current context.
        Plaintext must be an integer (int), a decimal that will get truncated (double),
        a PyPtxt encoded plaintext, or in Batch mode a 1D numpy vector of integers.
        Selects the encryption function based on type.
        
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (PyPtxt|int|double|np_1d_int_array): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """
        if not isinstance(ptxt, PLAINTEXT_T):
            raise TypeError('<Pyfhel ERROR> Plaintext type \['+type(ptxt)+
                            '\] not supported for encryption')
        if isinstance(ptxt, PyPtxt):
            return self.encryptPtxt(ptxt, ctxt)
        elif isinstance(ptxt, np.ndarray):
            if (ptxt.ndim is not 1) or (ptxt.dtype is not int):
                raise TypeError('<Pyfhel ERROR> Plaintext numpy array is not'
                                '1D vector of int values, cannot encrypt.')
            return self.encryptBatch(ptxt, ctxt)  
        elif isinstance(ptxt, float):
            return self.encryptValue(<float>ptxt, ctxt)   
        elif isinstance(ptxt, Number):
            return self.encryptValue(<int>ptxt, ctxt)  
    
    cpdef decrypt(self, PyCtxt ctxt, PyPtxt ptxt=None):
        pass