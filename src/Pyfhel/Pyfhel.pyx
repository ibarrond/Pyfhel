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
FLOAT_T = (float, np.float16, np.float32, np.float64)
VALUE_T = FLOAT_T + (int, np.ndarray)

# ------------------------- PYTHON IMPLEMENTATION -----------------------------
cdef class Pyfhel:

    def __cinit__(self):
        self.afseal = new Afseal()
    def __dealloc__(self):
        if self.afseal != NULL:
            del self.afseal

    # =========================================================================
    # ============================ CRYPTOGRAPHY ===============================
    # =========================================================================
    
    cpdef ContextGen(self, long p, long m=2048, bool flagBatching=False,
                     long base=2, long sec=128, int intDigits=64,
                     int fracDigits = 32) except +:
        """Generates Homomorphic Encryption context based on parameters.
        
        Creates a HE context based in parameters, as well as integer,
        fractional and batch encoders. The HE context is required for any 
        other function (encryption/decryption,encoding/decoding, operations).
        
        Batch encoding is available if p is prime and p-1 is multiple of 2*m.
        
        Args:
            p (long): Plaintext modulus. All operations are modulo p.
            m (long=2048): Coefficient modulus. Higher allows more encrypted 
                      operations. In batch mode it is the number of integers
                      per ciphertext.
            flagBatching (bool=false): Set to true to enable batching.
            base (long=2): Polynomial base. Affects size of plaintexts and 
                      ciphertexts, and FRACTIONAL encoding. See encryptFrac.
            sec (long=128): Security level equivalent in AES.
                      Either 128 or 192.
            intDigits (int=64): when encrypting/encoding double, truncated
                      positions dedicated to integer part, out of 'm' positions
            fracDigits (int=32): when encrypting/encoding double, truncated
                      positions dedicated to fractional part, out of 'm'
                      
        Return:
            None
        """
        self.afseal.ContextGen(p, m, flagBatching, base, sec,intDigits, fracDigits)
        
        
    cpdef void KeyGen(self) except +:
        """Generates a pair of Private/Public Keys.
        
        Based on the current context, initializes one public and one private key. 
        Args:
            None
                      
        Return:
            None
        """
        self.afseal.KeyGen()
    
    
    # .............................. ENCYRPTION ...............................
    cpdef PyCtxt encryptInt(self, int64_t value, PyCtxt ctxt=None) except +:
        """Encrypts a single int value into a PyCtxt ciphertext.
        
        Encrypts a single value using the current public key, based on the 
        current context. Value must either be an integer (int64_t)
        If provided a ciphertext, encrypts the value inside it. 
        
        Args:
            value (int): value to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
        """
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(value, deref(ctxt._ptr_ctxt))
        ctxt._encoding = ENCODING_T.INTEGER
        return ctxt
    
    cpdef PyCtxt encryptFrac(self, double value, PyCtxt ctxt=None) except +:
        """Encrypts a single float value into a PyCtxt ciphertext.
        based on the 
        Encrypts a single value using the current private key, based on the
        current context. Value must a decimal (float, double) that will get
        truncated both in the integer part (base^intDigits) and in the 
        decimal part (base^fracDigits).
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            value (float): value to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
        """
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(value, deref(ctxt._ptr_ctxt))
        ctxt._encoding = ENCODING_T.FRACTIONAL
        return ctxt
    
    cpdef PyCtxt encryptBatch(self, vector[int64_t] vec, PyCtxt ctxt=None) except +: 
        """Encrypts a 1D vector of integers into a PyCtxt ciphertext.
        
        Encrypts a 1D vector of integers using the current private key,
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
        
    cpdef PyCtxt encryptPtxt(self, PyPtxt ptxt, PyCtxt ctxt=None) except +:
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
            raise TypeError("<Pyfhel ERROR> PyPtxt Plaintext is empty")
        if (ctxt._ptr_ctxt == NULL):
            ctxt = PyCtxt()
        self.afseal.encrypt(deref(ptxt._ptr_ptxt), deref(ctxt._ptr_ctxt)) 
        ctxt._encoding = ptxt._encoding
        return ctxt

    def encrypt(self, ptxt not None, PyCtxt ctxt=None):
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
        else:
            raise TypeError('<Pyfhel ERROR> Plaintext type \['+type(ptxt)+
                            '\] not supported for encryption')
    
    # .............................. DECRYPTION ...............................
    cpdef int64_t decryptInt(self, PyCtxt ctxt, int64_t output_value = 0) except +:
        """Decrypts a PyCtxt ciphertext into a single int value.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on
        the current context. PyCtxt encoding must be INTEGER.
        
        Args:
            ctxt (PyCtxt=None): ciphertext to decrypt. 
            
        Return:
            int: the decrypted integer value
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.INTEGER.
        """
        if (ctxt._encoding == ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        self.afseal.decrypt(deref(ctxt._ptr_ctxt), output_value)
        return output_value
    
    cpdef double decryptFrac(self, PyCtxt ctxt, double output_value = 0) except +:
        """Decrypts a PyCtxt ciphertext into a single float value.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on
        the current context. PyCtxt encoding must be FRACTIONAL.
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            
        Return:
            float: the decrypted float value
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.FRACTIONAL.
        """
        if (ctxt._encoding == ENCODING_T.FRACTIONAL):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        self.afseal.decrypt(deref(ctxt._ptr_ctxt), output_value)
        return output_value
    
    cpdef vector[int64_t] decryptBatch(self, PyCtxt ctxt,
                   vector[int64_t] output_vector=[0]) except +:
                
        """Decrypts a PyCtxt ciphertext into a 1D numpy vector of integers.
        
        Decrypts a PyCtxt ciphertext  using the current private key, based on
        the current context. If provided an output vector, decrypts the
        ciphertext inside it. 
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            output_vector (vector[int]): Optional output vector
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.BATCH.
        """
        if (ctxt._encoding == ENCODING_T.BATCH):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        if (output_vector!= [0]):
            self.afseal.decrypt(deref(ctxt._ptr_ctxt), output_vector)
            return ctxt
        else:
            return self.afseal.decrypt(deref(ctxt._ptr_ctxt))
        
    cpdef PyPtxt decryptPtxt(self, PyCtxt ctxt, PyPtxt ptxt=None) except +:
        """Decrypts a PyCtxt ciphertext into a PyPtxt plaintext.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on
        the current context. No regard to encoding (decode PyPtxt to obtain 
        value).
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            ptxt (PyPtxt=None): Optional destination plaintext.
            
        Return:
            PyPtxt: the decrypted plaintext
        """
        if (ptxt._ptr_ptxt == NULL):
            ptxt = PyPtxt()
        self.afseal.decrypt(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
        ptxt._encoding = ctxt._encoding
        return ptxt
    
    def decrypt(self, PyCtxt ctxt, bool decrypt_value=False, PyPtxt ptxt=None):
        """Decrypts any valid PyCtxt into either a PyPtxt ciphertext or a value.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on the
        current context.
        Outputs an integer (int), a truncated decimal (float),
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
        if (decrypt_value):
            if (ctxt._encoding == ENCODING_T.BATCH):
                return self.decryptBatch(ctxt)
            elif (ctxt._encoding == ENCODING_T.FRACTIONAL):
                return self.decryptFrac(ctxt)
            elif (ctxt._encoding == ENCODING_T.INTEGER):
                return self.decryptInt(ctxt)
            elif (ctxt._encoding == ENCODING_T.UNDEFINED):
                raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        else: # Decrypt to plaintext        
            if (ptxt._ptr_ptxt == NULL):
                ptxt = PyPtxt()
            return self.decryptPtxt(ctxt, ptxt)
        
        
    # ............................. NOISE LEVEL ...............................
    cpdef int noiseLevel(PyCtxt ctxt) except +:
        """Computes the invariant noise budget (in bits) of a PyCtxt ciphertext.
        
        The invariant noise budget measures the amount of room there is for the
        noise to grow while ensuring correct decryptions.
        Decrypts a PyCtxt ciphertext using the current private key, based on the
        current context.
        
        Args:
            ctxt (PyCtxt): ciphertext to be measured.
            
        Return:
            int: the noise budget level
        """
        return self.afseal.noiseLevel(deref(ctxt._ptr_ctxt))
    

    
    # =========================================================================
    # ============================== ENCODING =================================
    # =========================================================================
    # ............................... ENCODE ..................................
    cpdef PyPtxt encodeInt(self, int64_t value, PyPtxt ptxt=None) except +:
        """Encodes a single int value into a PyPtxt plaintext.
        
        Encodes a single intvalue based on the current context.
        If provided a plaintext, encodes the value inside it. 
        
        Args:
            value (int): value to encrypt.
            ptxt (PyPtxt=None): Optional destination plaintext.  
            
        Return:
            PyPtxt: the plaintext containing the encoded value
        """
        if (ptxt._ptr_ptxt == NULL):
            ptxt = PyPtxt()
        self.afseal.encode(value, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.INTEGER
        return ptxt
    
    cpdef PyPtxt encodeFrac(self, double value, PyPtxt ptxt=None) except +:
        """Encodes a single float value into a PyPtxt plaintext.
        
        Encodes a single float value based on the current context.
        If provided a plaintext, encodes the value inside it. 
        
        Args:
            value (float): value to encrypt.
            ptxt (PyPtxt=None): Optional destination plaintext.   
            
        Return:
            PyPtxt: the plaintext containing the encoded value
        """
        if (ptxt._ptr_ptxt == NULL):
            ptxt = PyPtxt()
        self.afseal.encode(value, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.INTEGER
        return ptxt
    
    cpdef PyPtxt encodeBatch(self, vector[int64_t] vec, PyPtxt ptxt=None) except +: 
        """Encodes a 1D vector of integers into a PyPtxt plaintext.
        
        Encodes a 1D numpy vector of integers based on the current context.
        Plaintext must be a 1D vector of integers. Requires batch mode.
        In Numpy the vector needs to be in 'contiguous' or 'c' mode.
        If provided a plaintext, encodes the vector inside it. 
        Maximum size of the vector defined by parameter 'm' from context.
        
        Args:
            ptxt (np.ndarray[int, ndim=1, mode="c"]): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
        """
        if (ptxt._ptr_ptxt == NULL):
            ptxt = PyPtxt()
        self.afseal.encode(vec, deref(ptxt._ptr_ptxt))
        ptxt._encoding = ENCODING_T.BATCH
        return ptxt  

    def encode(self, val_vec not None, PyPtxt ptxt=None):
        """Encodes any valid value/vector into a PyPtxt plaintext.
        
        Encodes any valid value/vector based on the current context.
        Value/Vector must be an integer (int), a decimal that will get 
        truncated (double), or in Batch mode a 1D vector of 
        integers.
        
        If provided a ciphertext, encrypts the plaintext inside it. 
        
        Args:
            ptxt (PyPtxt|int|double|np_1d_int_array): plaintext to encrypt.
            ctxt (PyCtxt=None): Optional destination ciphertext.  
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            TypeError: if the plaintext doesn't have a valid type.
        """            
        if isinstance(val_vec, np.ndarray):
            if (val_vec.ndim is not 1) or (val_vec.dtype is not int):
                raise TypeError('<Pyfhel ERROR> Plaintext numpy array is not'
                                '1D vector of int values, cannot encode.')
            return self.encodeBatch(val_vec, ptxt)  
        elif isinstance(val_vec, FLOAT_T):
            return self.encodeValue(<float>val_vec, ptxt)   
        elif isinstance(ptxt, Number):
            return self.encryptValue(<int>ptxt, ctxt)  
        else:
            raise TypeError('<Pyfhel ERROR> Plaintext type \['+type(ptxt)+
                            '\] not supported for encryption')  
        elif isinstance(val_vec, Number):
            return self.encodeValue(<int>val_vec, ptxt)        

    # ................................ DECODE .................................
    cpdef int64_t decodeInt(self, PyPtxt ptxt, int64_t output_value = 0) except +:
        """Decodes a PyPtxt plaintext into a single int value.
        
        Decodes a PyPtxt plaintext into a single int value based on
        the current context. PyPtxt encoding must be INTEGER.
        
        Args:
            ptxt (PyPtxt=None): plaintext to decode. 
            
        Return:
            int: the decoded integer value
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.INTEGER.
        """
        if (ptxt._encoding == ENCODING_T.INTEGER):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyPtxt")
        self.afseal.decode(deref(ptxt_ptr_ptxt), output_value)
        return output_value
    
    cpdef double decodeFrac(self, PyPtxt ptxt, double output_value = 0) except +:
        """Decodes a PyPtxt plaintext into a single float value.
        
        Decodes a PyPtxt plaintext into a single float value based on
        the current context. PyPtxt encoding must be FRACTIONAL.
        
        Args:
            ptxt (PyPtxt=None): plaintext to decode. 
            
        Return:
            float: the decoded float value
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.FRACTIONAL.
        """
        if (ptxt._encoding == ENCODING_T.FRACTIONAL):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        self.afseal.decrypt(deref(ptxt._ptr_ptxt), output_value)
        return output_value
    
    cpdef vector[int64_t] decodeBatch(self, PyCtxt ctxt,
                   vector[int64_t] output_vector=[0]) except +:
                
        """Decrypts a PyCtxt ciphertext into a 1D numpy vector of integers.
        
        Decrypts a PyCtxt ciphertext  using the current private key, based on
        the current context. If provided an output vector, decrypts the
        ciphertext inside it. 
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            output_vector (vector[int]): Optional output vector
            
        Return:
            PyCtxt: the ciphertext containing the encrypted plaintext
            
        Raise:
            RuntimeError: if the ciphertext encoding isn't ENCODING_T.BATCH.
        """
        if (ctxt._encoding == ENCODING_T.BATCH):
            raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        if (output_vector!= [0]):
            self.afseal.decrypt(deref(ctxt._ptr_ctxt), output_vector)
            return ctxt
        else:
            return self.afseal.decrypt(deref(ctxt._ptr_ctxt))
        
    cpdef PyPtxt decryptPtxt(self, PyCtxt ctxt, PyPtxt ptxt=None) except +:
        """Decrypts a PyCtxt ciphertext into a PyPtxt plaintext.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on
        the current context. No regard to encoding (decode PyPtxt to obtain 
        value).
        
        Args:
            ctxt (PyCtxt): ciphertext to decrypt. 
            ptxt (PyPtxt=None): Optional destination plaintext.
            
        Return:
            PyPtxt: the decrypted plaintext
        """
        if (ptxt._ptr_ptxt == NULL):
            ptxt = PyPtxt()
        self.afseal.decrypt(deref(ctxt._ptr_ctxt), deref(ptxt._ptr_ptxt))
        ptxt._encoding = ctxt._encoding
        return ptxt
    
    def decrypt(self, PyCtxt ctxt, bool decrypt_value=False, PyPtxt ptxt=None):
        """Decrypts any valid PyCtxt into either a PyPtxt ciphertext or a value.
        
        Decrypts a PyCtxt ciphertext using the current private key, based on the
        current context.
        Outputs an integer (int), a truncated decimal (float),
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
        if (decrypt_value):
            if (ctxt._encoding == ENCODING_T.BATCH):
                return self.decryptBatch(ctxt)
            elif (ctxt._encoding == ENCODING_T.FRACTIONAL):
                return self.decryptFrac(ctxt)
            elif (ctxt._encoding == ENCODING_T.INTEGER):
                return self.decryptInt(ctxt)
            elif (ctxt._encoding == ENCODING_T.UNDEFINED):
                raise RuntimeError("<Pyfhel ERROR> wrong encoding type in PyCtxt")
        else: # Decrypt to plaintext        
            if (ptxt._ptr_ptxt == NULL):
                ptxt = PyPtxt()
            return self.decryptPtxt(ctxt, ptxt)