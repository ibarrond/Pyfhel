import unittest
from Pyfhel import Pyfhel
from PyCtxt import PyCtxt
from PyPtxt import PyPtxt

class PyfhelTestCase(unittest.TestCase):
    def setUp(self):
        
        self.pyfhel = Pyfhel()
        print("Here i am")

    def test_context_gen(self):
        self.pyfhel.ContextGen(65537)

    def test_key_gen(self):
        self.pyfhel.KeyGen()    
        
    def test_relin_key_gen(self):
        self.assertRaises(ValueError, self.pyfhel.relinKeyGen(61))
        self.assertRaises(ValueError, self.pyfhel.relinKeyGen(0))
        self.pyfhel.relinKeyGen(60)     
        self.pyfhel.relinKeyGen(1) 
        
    def test_rotate_key_gen(self):
        self.assertRaises(ValueError, self.pyfhel.rotateKeyGen(61))
        self.assertRaises(ValueError, self.pyfhel.rotateKeyGen(0))
        self.pyfhel.rotateKeyGen(60)     
        self.pyfhel.rotateKeyGen(1)     
        
    def test_widget_resize(self):
        self.ctxt = self.pyfhel.encrypt(3)
        
if __name__ == '__main__':
    unittest.main()