
# Global modules
import unittest
import time
import sys
import numpy as np

# Local module
from Pyfhel import Pyfhel
from PyCtxt import PyCtxt
from PyPtxt import PyPtxt

from util import ENCODING_t

# Value of p for batching: p=1964769281

class PyfhelTestCase(unittest.TestCase):
    
    def setUp(self):
        self.t0 = time.time()

    def tearDown(self):
        sys.stderr.write('({}s) ...'.format(
            round(time.time() - self.t0 , 3)))
             
    def test_PyPtxt_creation_deletion(self):    
        try:
            self.ptxt = PyPtxt()
        except Exception as err:
            self.fail("PyPtxt() creation failed unexpectedly: ", err)
        self.assertEqual(self.ptxt._encoding, ENCODING_t.UNDEFINED)
        self.ptxt._encoding=ENCODING_t.INTEGER
        self.assertEqual(self.ptxt._encoding, ENCODING_t.INTEGER)
        del(self.ptxt._encoding)
        self.assertEqual(self.ptxt._encoding, ENCODING_t.UNDEFINED)
        try:
            del(self.ptxt)
        except Exception as err:
            self.fail("PyPtxt() deletion failed unexpectedly: ", err)
        
    def test_PyCtxt_creation_deletion(self):    
        try:
            self.ctxt = PyCtxt()
        except Exception as err:
            self.fail("PyCtxt() creation failed unexpectedly: ", err)
        self.assertEqual(self.ctxt.size(), 2)
        self.assertEqual(self.ctxt._encoding, ENCODING_t.UNDEFINED)
        self.ctxt._encoding=ENCODING_t.FRACTIONAL
        self.assertEqual(self.ctxt._encoding, ENCODING_t.FRACTIONAL)
        del(self.ctxt._encoding)
        self.assertEqual(self.ctxt._encoding, ENCODING_t.UNDEFINED)
        self.assertEqual(self.ctxt.size(), 2)    
        try:
            del(self.ctxt)
        except Exception as err:
            self.fail("PyCtxt() deletion failed unexpectedly: ", err)
        
    def test_Pyfhel_1_creation_deletion(self):    
        try:
            self.pyfhel = Pyfhel()
        except Exception as err:
            self.fail("Pyfhel() creation failed unexpectedly: ", err)
        try:
            del(self.pyfhel)
        except Exception as err:
            self.fail("Pyfhel() deletion failed unexpectedly: ", err)
            
    def test_Pyfhel_2_context_n_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(65537)
        self.pyfhel.KeyGen() 
        
    def test_Pyfhel_3_rotate_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(65537)
        self.pyfhel.KeyGen() 
        self.pyfhel.rotateKeyGen(30)
        self.pyfhel.rotateKeyGen(1)  
        self.pyfhel.rotateKeyGen(60) 
        self.assertRaises(SystemError, lambda: self.pyfhel.rotateKeyGen(61))
        self.assertRaises(SystemError, lambda: self.pyfhel.rotateKeyGen(0))
        
    def test_Pyfhel_4_relin_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(65537)
        self.pyfhel.KeyGen() 
        self.pyfhel.relinKeyGen(30)
        self.pyfhel.relinKeyGen(1)  
        self.pyfhel.relinKeyGen(60) 
        self.assertRaises(SystemError, lambda: self.pyfhel.relinKeyGen(61))
        self.assertRaises(SystemError, lambda: self.pyfhel.relinKeyGen(0))
        
    def test_Pyfhel_encode_int(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(p=65537)
        self.pyfhel.KeyGen() 
        self.ptxt = self.pyfhel.encodeInt(127)
        self.assertEqual(self.ptxt.to_string(), b'1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1')
        self.pyfhel.encodeInt(2, self.ptxt)
        self.assertEqual(self.ptxt.to_string(), b'1x^1')
                        
    def test_Pyfhel_encode_float(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(p=10, m=8192, base=2, intDigits = 80, fracDigits = 20)
        self.pyfhel.KeyGen() 
        self.ptxt = self.pyfhel.encodeFrac(19.30)
        self.assertTrue(self.ptxt.to_string(), b'9x^8190 + 1x^4 + 1x^1 + 1')
        self.pyfhel.encodeInt(2, self.ptxt)
        self.assertTrue(self.ptxt.to_string(), b'1x^1')
            
    def test_Pyfhel_encode_array(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.ContextGen(p=1964769281, m=8192, base=3, sec=192)
        self.pyfhel.KeyGen() 
        self.assertTrue(self.pyfhel.batchEnabled())
        # self.assertEqual(self.pyfhel.getnSlots(), 8192)
        #self.ptxt = self.pyfhel.encodeBatch([2,3])
        #print(self.ptxt.to_string())      
            
if __name__ == '__main__':
    unittest.main(verbosity=2)