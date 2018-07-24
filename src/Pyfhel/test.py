import unittest
import time
import sys

from Pyfhel import Pyfhel
from PyCtxt import PyCtxt
from PyPtxt import PyPtxt

pyfhel = Pyfhel()
pyfhel.ContextGen(65537)
pyfhel.KeyGen() 

class PyfhelTestCase(unittest.TestCase):
    
    def setUp(self):
        self.t0 = time.time()

    def tearDown(self):
        sys.stderr.write('({}s) ...'.format(
            round(time.time() - self.t0 , 3)))
             
    def test_PyPtxt(self):
        from util import ENCODING_t
        self.ptxt = PyPtxt()
        assertTrue(ptxt
            
    def test_encrypt(self):
        ctxt=PyCtxt()
        
    def test_relin_key_gen(self):
        with self.assertRaises(SystemError):
            pyfhel.relinKeyGen(61)
        with self.assertRaises(SystemError):
            pyfhel.relinKeyGen(0)
        pyfhel.relinKeyGen(60)     
        pyfhel.relinKeyGen(1) 
        
    def test_rotate_key_gen(self):
        with self.assertRaises(SystemError):
            pyfhel.rotateKeyGen(61)
        with self.assertRaises(SystemError):
            pyfhel.rotateKeyGen(0)
        pyfhel.rotateKeyGen(60)     
        pyfhel.rotateKeyGen(1)     
        
    def test_encrypt(self):
        ctxt=PyCtxt()
        self.ctxt = pyfhel.encryptInt(3, ctxt)
        
if __name__ == '__main__':
    unittest.main()