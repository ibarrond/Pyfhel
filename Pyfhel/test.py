
# Global modules
import unittest
import time
import sys
import os
import numpy as np

# Local module
from Pyfhel import Pyfhel
from Pyfhel import PyCtxt
from Pyfhel import PyPtxt

from Pyfhel.util import ENCODING_t

# Value of p for batching: p=1964769281

class PyfhelTestCase(unittest.TestCase):
    
    def setUp(self):
        self.t0 = time.time()

    def tearDown(self):
        sys.stderr.write('({}s) ...'.format(
            round(time.time() - self.t0 , 3)))
    def test_PyPtxt_PyCtxt(self):
        pass
    def test_PyPtxt_creation_deletion(self):    
        try:
            self.ptxt = PyPtxt()
            self.ptxt2 = PyPtxt(other_ptxt=self.ptxt)
            self.pyfhel = Pyfhel()
            self.ptxt3 = PyPtxt(pyfhel=self.pyfhel)
            self.ptxt4 = PyPtxt(other_ptxt=self.ptxt3)
        except Exception as err:
            self.fail("PyPtxt() creation failed unexpectedly: ", err)
        self.assertEqual(self.ptxt._encoding, ENCODING_t.UNDEFINED)
        self.ptxt._encoding=ENCODING_t.INTEGER
        self.assertEqual(self.ptxt._encoding, ENCODING_t.INTEGER)
        del(self.ptxt._encoding)
        self.assertEqual(self.ptxt._encoding, ENCODING_t.UNDEFINED)
        self.ptxt._pyfhel=self.pyfhel
        self.ptxt2._pyfhel = self.ptxt._pyfhel
        try:
            del(self.ptxt)
        except Exception as err:
            self.fail("PyPtxt() deletion failed unexpectedly: ", err)
        
    def test_PyCtxt_creation_deletion(self):    
        try:
            self.ctxt = PyCtxt()
            self.ctxt2 = PyCtxt(other_ctxt=self.ctxt)
            self.pyfhel = Pyfhel()
            self.ctxt3 = PyCtxt(pyfhel=self.pyfhel)
            self.ctxt4 = PyCtxt(other_ctxt=self.ctxt3)
        except Exception as err:
            self.fail("PyCtxt() creation failed unexpectedly: ", err)
        self.assertEqual(self.ctxt.size(), 2)
        self.assertEqual(self.ctxt._encoding, ENCODING_t.UNDEFINED)
        self.ctxt._encoding=ENCODING_t.FRACTIONAL
        self.assertEqual(self.ctxt._encoding, ENCODING_t.FRACTIONAL)
        del(self.ctxt._encoding)
        self.assertEqual(self.ctxt._encoding, ENCODING_t.UNDEFINED)
        self.assertEqual(self.ctxt.size(), 2)    
        self.ctxt._pyfhel=self.pyfhel
        self.ctxt2._pyfhel = self.ctxt._pyfhel
        try:
            del(self.ctxt)
        except Exception as err:
            self.fail("PyCtxt() deletion failed unexpectedly: ", err)
        
    def test_Pyfhel_1_GENERATION(self):
        pass
    def test_Pyfhel_1a_creation_deletion(self):    
        try:
            self.pyfhel = Pyfhel()
        except Exception as err:
            self.fail("Pyfhel() creation failed unexpectedly: ", err)
        try:
            del(self.pyfhel)
        except Exception as err:
            self.fail("Pyfhel() deletion failed unexpectedly: ", err)
            
    def test_Pyfhel_1b_context_n_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(65537)
        self.pyfhel.keyGen() 
        
    def test_Pyfhel_1c_rotate_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(65537)
        self.pyfhel.keyGen() 
        self.pyfhel.rotateKeyGen(30)
        self.pyfhel.rotateKeyGen(1)  
        self.pyfhel.rotateKeyGen(60) 
        self.assertRaises(SystemError, lambda: self.pyfhel.rotateKeyGen(61))
        self.assertRaises(SystemError, lambda: self.pyfhel.rotateKeyGen(0))
        
    def test_Pyfhel_1d_relin_key_generation(self):  
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(65537)
        self.pyfhel.keyGen() 
        self.pyfhel.relinKeyGen(30, 5)
        self.pyfhel.relinKeyGen(1, 5)  
        self.pyfhel.relinKeyGen(60, 5) 
        self.assertRaises(SystemError, lambda: self.pyfhel.relinKeyGen(61, 5))
        self.assertRaises(SystemError, lambda: self.pyfhel.relinKeyGen(0, 5))
        
    def test_Pyfhel_2_ENCODING(self):
        pass
    
    def test_Pyfhel_2a_encode_decode_int(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=65537)
        self.pyfhel.keyGen() 
        self.ptxt = self.pyfhel.encodeInt(127)
        self.assertEqual(self.ptxt.to_string(), b'1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1')
        self.assertEqual(self.pyfhel.decodeInt(self.ptxt), 127)
        self.ptxt2 = PyPtxt(self.ptxt)
        self.pyfhel.encodeInt(-2, self.ptxt)
        self.assertEqual(self.ptxt.to_string(),  b'10000x^1')
        self.assertEqual(self.pyfhel.decodeInt(self.ptxt), -2)
        self.assertEqual(self.pyfhel.decodeInt(self.ptxt2), 127)
                        
    def test_Pyfhel_2b_encode_decode_float(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=65537, m=8192, base=2, intDigits = 80, fracDigits = 20)
        self.pyfhel.keyGen() 
        self.ptxt = self.pyfhel.encodeFrac(19.30)
        self.assertTrue(self.ptxt.to_string(), b'9x^8190 + 1x^4 + 1x^1 + 1')
        self.assertEqual(round(self.pyfhel.decodeFrac(self.ptxt), 2), 19.30)
        self.pyfhel.encodeFrac(-2.25, self.ptxt)
        self.assertEqual(self.ptxt.to_string(),  b'1x^8190 + 10000x^1')
        self.assertEqual(round(self.pyfhel.decodeFrac(self.ptxt), 2), -2.25)
    
            
    def test_Pyfhel_2c_encode_decode_batch(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.assertTrue(self.pyfhel.batchEnabled())
        self.ptxt = self.pyfhel.encodeBatch([1, 2, 3, 4, 5, 6])
        self.assertEqual(self.pyfhel.getnSlots(), 8192)
        self.assertEqual(self.pyfhel.decodeBatch(self.ptxt)[:6], [1, 2, 3, 4, 5, 6])
        
        #print(self.ptxt.to_string())
        
    def test_Pyfhel_2d_encode_decode_array(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.assertTrue(self.pyfhel.batchEnabled())
        self.ptxt = self.pyfhel.encodeArray(np.array([1, 2, 3, 4, 5, 6]))
        self.assertEqual(self.pyfhel.getnSlots(), 8192)
        self.assertTrue(np.alltrue(self.pyfhel.decodeArray(self.ptxt)[:6] == np.array([1, 2, 3, 4, 5, 6])))
            
    def test_Pyfhel_3_ENCRYPTING(self):
        pass
    
    def test_Pyfhel_3a_encrypt_decrypt_int(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=65537)
        self.pyfhel.keyGen() 
        self.ctxt = self.pyfhel.encryptInt(127)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt), 127)
        self.ctxt2 = PyCtxt(self.ctxt)
        self.pyfhel.encryptInt(-2, self.ctxt)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt), -2)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt), -2)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt2), 127)
                        
    def test_Pyfhel_3b_encrypt_decrypt_float(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=65537, m=8192, base=2, intDigits = 80, fracDigits = 20)
        self.pyfhel.keyGen() 
        self.ctxt = self.pyfhel.encryptFrac(19.30)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt), 2), 19.30)
        self.pyfhel.encryptFrac(-2.25, self.ctxt)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt), 2), -2.25)
    
            
    def test_Pyfhel_3c_encrypt_decrypt_batch(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.assertTrue(self.pyfhel.batchEnabled())
        self.ctxt = self.pyfhel.encryptBatch([1, 2, 3, 4, 5, 6])
        self.assertEqual(self.pyfhel.getnSlots(), 8192)
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt)[:6], [1, 2, 3, 4, 5, 6])
        
        #print(self.ptxt.to_string())
        
    def test_Pyfhel_3d_encrypt_decrypt_array(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.assertTrue(self.pyfhel.batchEnabled())
        self.ctxt = self.pyfhel.encryptArray(np.array([1, 2, 3, 4, 5, 6]))
        self.assertEqual(self.pyfhel.getnSlots(), 8192)
        self.assertTrue(np.alltrue(self.pyfhel.decryptArray(self.ctxt)[:6] == np.array([1, 2, 3, 4, 5, 6])))
            
    def test_Pyfhel_4_OPERATIONS(self):
        pass
        
    def test_Pyfhel_4a_operations_integer(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=3, sec=192)
        self.pyfhel.keyGen() 
        #self.pyfhel.rotateKeyGen(60) 
        #self.pyfhel.relinKeyGen(60)
        
        self.ctxti = self.pyfhel.encryptInt(127)
        self.ctxti2 = self.pyfhel.encryptInt(-2)
        self.ptxti = self.pyfhel.encodeInt(3)
        
        self.ctxt_add = self.pyfhel.add(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_add2 = self.pyfhel.add_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_sub = self.pyfhel.sub(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_sub2 = self.pyfhel.sub_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_mult = self.pyfhel.multiply(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_mult2 = self.pyfhel.multiply_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        #self.ctxt_rotate = self.pyfhel.rotate(self.ctxti, 2)
        #self.ctxt_expon = self.pyfhel.power(self.ctxti, 3)
        #self.ctxt_expon2 = self.pyfhel.power(self.ctxti2, 3)
        #self.ctxt_polyEval = self.pyfhel.polyEval(self.ctxti, [1, 2, 1], in_new_ctxt=True)
        
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_add), 125)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_add2), 130)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_sub), 129)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_sub2), 124)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_mult), -254)
        self.assertEqual(self.pyfhel.decryptInt(self.ctxt_mult2), 381)
        #self.assertEqual(self.pyfhel.decryptInt(self.ctxt_expon), 2048383)
        #self.assertEqual(self.pyfhel.decryptInt(self.ctxt_expon2), -8)
        #self.assertEqual(self.pyfhel.decryptInt(self.ctxt_polyEval), 16510)
        
        
        
    def test_Pyfhel_4b_operations_frac(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=3, sec=192)
        self.pyfhel.keyGen() 
        #self.pyfhel.rotateKeyGen(60) 
        #self.pyfhel.relinKeyGen(60)
        
        self.ctxti = self.pyfhel.encryptFrac(19.37)
        self.ctxti2 = self.pyfhel.encryptFrac(-2.25)
        self.ptxti = self.pyfhel.encodeFrac(3.12)
        
        self.ctxt_add = self.pyfhel.add(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_add2 = self.pyfhel.add_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_sub = self.pyfhel.sub(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_sub2 = self.pyfhel.sub_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_mult = self.pyfhel.multiply(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_mult2 = self.pyfhel.multiply_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_add),2), 17.12)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_add2),2), 22.49)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_sub),2), 21.62)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_sub2),2), 16.25)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_mult),2), -43.58)
        self.assertEqual(round(self.pyfhel.decryptFrac(self.ctxt_mult2),2), 60.43)
        
    def test_Pyfhel_4c_operations_batch_array(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.pyfhel.rotateKeyGen(60) 
        self.ctxti = self.pyfhel.encryptBatch([1, 2, 3, 4, 5, 6])
        self.ctxti2 = self.pyfhel.encryptArray(np.array([-6, -5, -4, -3, -2, -1]))
        self.ptxti = self.pyfhel.encodeArray(np.array([12, 15, 18, 21, 24, 27]))
        
        self.ctxt_add = self.pyfhel.add(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_add2 = self.pyfhel.add_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_sub = self.pyfhel.sub(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_sub2 = self.pyfhel.sub_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_mult = self.pyfhel.multiply(self.ctxti, self.ctxti2, in_new_ctxt=True)
        self.ctxt_mult2 = self.pyfhel.multiply_plain(self.ctxti, self.ptxti, in_new_ctxt=True)
        self.ctxt_rotate = self.pyfhel.rotate(self.ctxti, -2, in_new_ctxt=True)
        self.ctxt_rotate2 = self.pyfhel.rotate(self.ctxti, 2, in_new_ctxt=True)
        #self.ctxt_expon = self.pyfhel.power(self.ctxti, 3)
        #self.ctxt_expon2 = self.pyfhel.power(self.ctxti2, 3)
        #self.ctxt_polyEval = self.pyfhel.polyEval(self.ctxti, [1, 2, 1], in_new_ctxt=True)
        
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_add)[:6], [-5, -3, -1, 1, 3, 5])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_add2)[:6], [13, 17, 21, 25, 29, 33])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_sub)[:6], [7, 7, 7, 7, 7, 7])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_sub2)[:6], [-11, -13, -15, -17, -19, -21])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_mult)[:6],  [-6, -10, -12, -12, -10, -6])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_mult2)[:6], [12, 30, 54, 84, 120, 162])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_rotate)[:6], [0, 0, 1, 2, 3, 4])
        self.assertEqual(self.pyfhel.decryptBatch(self.ctxt_rotate2)[:6], [3, 4, 5, 6, 0, 0])
        
        
    def test_Pyfhel_5_IO_SAVE_RESTORE(self):
        pass
    
    def test_Pyfhel_5a_save_objects(self):
        self.pyfhel = Pyfhel()
        self.pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        self.pyfhel.keyGen() 
        self.pyfhel.rotateKeyGen(60)
        #self.pyfhel.relinKeyGen(60)
        
        self.assertTrue(self.pyfhel.saveContext(b"context.pycon"))
        self.assertTrue(self.pyfhel.savepublicKey(b"public_k.pypk"))
        self.assertTrue(self.pyfhel.savesecretKey(b"secret_k.pysk"))
        #self.assertTrue(self.pyfhel.saverelinKey(b"relin_k.pyrlk"))
        self.assertTrue(self.pyfhel.saverotateKey(b"rotate_k.pyrok"))
        
    def test_Pyfhel_5b_restore_objects(self):  
        self.pyfhel = Pyfhel()  
        self.assertTrue(self.pyfhel.restoreContext(b"context.pycon"))
        self.assertTrue(self.pyfhel.restoresecretKey(b"secret_k.pysk"))
        self.assertTrue(self.pyfhel.restorepublicKey(b"public_k.pypk"))
        #self.assertTrue(self.pyfhel.restorerelinKey(b"relin_k.pyrlk"))
        self.assertTrue(self.pyfhel.restorerotateKey(b"rotate_k.pyrok"))
        os.remove(b"context.pycon")
        os.remove(b"secret_k.pysk")
        os.remove(b"public_k.pypk")
        os.remove(b"rotate_k.pyrok")
        
        # save/restore ciphertexts and plaintexts
if __name__ == '__main__':
    unittest.main(verbosity=2)
