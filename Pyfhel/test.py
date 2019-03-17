# Global modules
import os
import sys
import tempfile
import time
import unittest

import numpy as np
# Local module
from Pyfhel import PyCtxt, Pyfhel, PyPtxt
from Pyfhel.util import ENCODING_t

# Value of p for batching: p=1964769281


class PyfhelTestCase(unittest.TestCase):
    def setUp(self):
        self.t0 = time.time()

    def tearDown(self):
        sys.stderr.write("({}s) ...".format(round(time.time() - self.t0, 3)))

    def test_PyPtxt_PyCtxt(self):
        pass

    def test_PyPtxt_creation_deletion(self):
        try:
            ptxt = PyPtxt()
            ptxt2 = PyPtxt(other_ptxt=ptxt)
            pyfhel = Pyfhel()
            ptxt3 = PyPtxt(pyfhel=pyfhel)
            ptxt4 = PyPtxt(other_ptxt=ptxt3)
        except Exception as err:
            self.fail("PyPtxt() creation failed unexpectedly: ", err)
        self.assertEqual(ptxt._encoding, ENCODING_t.UNDEFINED)
        ptxt._encoding = ENCODING_t.INTEGER
        self.assertEqual(ptxt._encoding, ENCODING_t.INTEGER)
        del (ptxt._encoding)
        self.assertEqual(ptxt._encoding, ENCODING_t.UNDEFINED)
        ptxt._pyfhel = pyfhel
        ptxt2._pyfhel = ptxt._pyfhel
        try:
            del (ptxt)
        except Exception as err:
            self.fail("PyPtxt() deletion failed unexpectedly: ", err)

    def test_PyCtxt_creation_deletion(self):
        try:
            ctxt = PyCtxt()
            ctxt2 = PyCtxt(other_ctxt=ctxt)
            pyfhel = Pyfhel()
            ctxt3 = PyCtxt(pyfhel=pyfhel)
            ctxt4 = PyCtxt(other_ctxt=ctxt3)
        except Exception as err:
            self.fail("PyCtxt() creation failed unexpectedly: ", err)
        self.assertEqual(ctxt.size(), 2)
        self.assertEqual(ctxt._encoding, ENCODING_t.UNDEFINED)
        ctxt._encoding = ENCODING_t.FRACTIONAL
        self.assertEqual(ctxt._encoding, ENCODING_t.FRACTIONAL)
        del (ctxt._encoding)
        self.assertEqual(ctxt._encoding, ENCODING_t.UNDEFINED)
        self.assertEqual(ctxt.size(), 2)
        ctxt._pyfhel = pyfhel
        ctxt2._pyfhel = ctxt._pyfhel
        try:
            del (ctxt)
        except Exception as err:
            self.fail("PyCtxt() deletion failed unexpectedly: ", err)

    def test_Pyfhel_1_GENERATION(self):
        pass

    def test_Pyfhel_1a_creation_deletion(self):
        try:
            pyfhel = Pyfhel()
        except Exception as err:
            self.fail("Pyfhel() creation failed unexpectedly: ", err)
        try:
            del (pyfhel)
        except Exception as err:
            self.fail("Pyfhel() deletion failed unexpectedly: ", err)

    def test_Pyfhel_1b_context_n_key_generation(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(65537)
        pyfhel.keyGen()

    def test_Pyfhel_1c_rotate_key_generation(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(65537)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(30)
        pyfhel.rotateKeyGen(1)
        pyfhel.rotateKeyGen(60)
        self.assertRaises(SystemError, lambda: pyfhel.rotateKeyGen(61))
        self.assertRaises(SystemError, lambda: pyfhel.rotateKeyGen(0))

    def test_Pyfhel_1d_relin_key_generation(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(65537)
        pyfhel.keyGen()
        pyfhel.relinKeyGen(30, 5)
        pyfhel.relinKeyGen(1, 5)
        pyfhel.relinKeyGen(60, 5)
        self.assertRaises(SystemError, lambda: pyfhel.relinKeyGen(61, 5))
        self.assertRaises(SystemError, lambda: pyfhel.relinKeyGen(0, 5))

    def test_Pyfhel_2_ENCODING(self):
        pass

    def test_Pyfhel_2a_encode_decode_int(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=65537)
        pyfhel.keyGen()
        ptxt = pyfhel.encodeInt(127)
        self.assertEqual(
            ptxt.to_string(), b"1x^6 + 1x^5 + 1x^4 + 1x^3 + 1x^2 + 1x^1 + 1"
        )
        self.assertEqual(pyfhel.decodeInt(ptxt), 127)
        ptxt2 = PyPtxt(ptxt)
        pyfhel.encodeInt(-2, ptxt)
        self.assertEqual(ptxt.to_string(), b"10000x^1")
        self.assertEqual(pyfhel.decodeInt(ptxt), -2)
        self.assertEqual(pyfhel.decodeInt(ptxt2), 127)

    def test_Pyfhel_2b_encode_decode_float(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=65537, m=8192, base=2, intDigits=80, fracDigits=20)
        pyfhel.keyGen()
        ptxt = pyfhel.encodeFrac(19.30)
        self.assertTrue(ptxt.to_string(), b"9x^8190 + 1x^4 + 1x^1 + 1")
        self.assertEqual(round(pyfhel.decodeFrac(ptxt), 2), 19.30)
        pyfhel.encodeFrac(-2.25, ptxt)
        self.assertEqual(ptxt.to_string(), b"1x^8190 + 10000x^1")
        self.assertEqual(round(pyfhel.decodeFrac(ptxt), 2), -2.25)

    def test_Pyfhel_2c_encode_decode_batch(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        self.assertTrue(pyfhel.batchEnabled())
        ptxt = pyfhel.encodeBatch([1, 2, 3, 4, 5, 6])
        self.assertEqual(pyfhel.getnSlots(), 8192)
        self.assertEqual(pyfhel.decodeBatch(ptxt)[:6], [1, 2, 3, 4, 5, 6])

        # print(self.ptxt.to_string())

    def test_Pyfhel_2d_encode_decode_array(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        self.assertTrue(pyfhel.batchEnabled())
        ptxt = pyfhel.encodeArray(np.array([1, 2, 3, 4, 5, 6]))
        self.assertEqual(pyfhel.getnSlots(), 8192)
        self.assertTrue(
            np.alltrue(pyfhel.decodeArray(ptxt)[:6] == np.array([1, 2, 3, 4, 5, 6]))
        )

    def test_Pyfhel_3_ENCRYPTING(self):
        pass

    def test_Pyfhel_3a_encrypt_decrypt_int(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=65537)
        pyfhel.keyGen()
        ctxt = pyfhel.encryptInt(127)
        self.assertEqual(pyfhel.decryptInt(ctxt), 127)
        ctxt2 = PyCtxt(ctxt)
        pyfhel.encryptInt(-2, ctxt)
        self.assertEqual(pyfhel.decryptInt(ctxt), -2)
        self.assertEqual(pyfhel.decryptInt(ctxt), -2)
        self.assertEqual(pyfhel.decryptInt(ctxt2), 127)

    def test_Pyfhel_3b_encrypt_decrypt_float(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=65537, m=8192, base=2, intDigits=80, fracDigits=20)
        pyfhel.keyGen()
        ctxt = pyfhel.encryptFrac(19.30)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt), 2), 19.30)
        pyfhel.encryptFrac(-2.25, ctxt)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt), 2), -2.25)

    def test_Pyfhel_3c_encrypt_decrypt_batch(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        self.assertTrue(pyfhel.batchEnabled())
        ctxt = pyfhel.encryptBatch([1, 2, 3, 4, 5, 6])
        self.assertEqual(pyfhel.getnSlots(), 8192)
        self.assertEqual(pyfhel.decryptBatch(ctxt)[:6], [1, 2, 3, 4, 5, 6])

        # print(self.ptxt.to_string())

    def test_Pyfhel_3d_encrypt_decrypt_array(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        self.assertTrue(pyfhel.batchEnabled())
        ctxt = pyfhel.encryptArray(np.array([1, 2, 3, 4, 5, 6]))
        self.assertEqual(pyfhel.getnSlots(), 8192)
        self.assertTrue(
            np.alltrue(pyfhel.decryptArray(ctxt)[:6] == np.array([1, 2, 3, 4, 5, 6]))
        )

    def test_Pyfhel_4_OPERATIONS(self):
        pass

    def test_Pyfhel_4a_operations_integer(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=3, sec=192)
        pyfhel.keyGen()
        # self.pyfhel.rotateKeyGen(60)
        # self.pyfhel.relinKeyGen(60)

        ctxti = pyfhel.encryptInt(127)
        ctxti2 = pyfhel.encryptInt(-2)
        ptxti = pyfhel.encodeInt(3)

        ctxt_add = pyfhel.add(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_add2 = pyfhel.add_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_sub = pyfhel.sub(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_sub2 = pyfhel.sub_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_mult = pyfhel.multiply(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_mult2 = pyfhel.multiply_plain(ctxti, ptxti, in_new_ctxt=True)
        # self.ctxt_rotate = self.pyfhel.rotate(self.ctxti, 2)
        # self.ctxt_expon = self.pyfhel.power(self.ctxti, 3)
        # self.ctxt_expon2 = self.pyfhel.power(self.ctxti2, 3)
        # self.ctxt_polyEval = self.pyfhel.polyEval(self.ctxti, [1, 2, 1], in_new_ctxt=True)

        self.assertEqual(pyfhel.decryptInt(ctxt_add), 125)
        self.assertEqual(pyfhel.decryptInt(ctxt_add2), 130)
        self.assertEqual(pyfhel.decryptInt(ctxt_sub), 129)
        self.assertEqual(pyfhel.decryptInt(ctxt_sub2), 124)
        self.assertEqual(pyfhel.decryptInt(ctxt_mult), -254)
        self.assertEqual(pyfhel.decryptInt(ctxt_mult2), 381)
        # self.assertEqual(self.pyfhel.decryptInt(self.ctxt_expon), 2048383)
        # self.assertEqual(self.pyfhel.decryptInt(self.ctxt_expon2), -8)
        # self.assertEqual(self.pyfhel.decryptInt(self.ctxt_polyEval), 16510)

    def test_Pyfhel_4b_operations_frac(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=3, sec=192)
        pyfhel.keyGen()
        # self.pyfhel.rotateKeyGen(60)
        # self.pyfhel.relinKeyGen(60)

        ctxti = pyfhel.encryptFrac(19.37)
        ctxti2 = pyfhel.encryptFrac(-2.25)
        ptxti = pyfhel.encodeFrac(3.12)

        ctxt_add = pyfhel.add(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_add2 = pyfhel.add_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_sub = pyfhel.sub(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_sub2 = pyfhel.sub_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_mult = pyfhel.multiply(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_mult2 = pyfhel.multiply_plain(ctxti, ptxti, in_new_ctxt=True)

        self.assertEqual(round(pyfhel.decryptFrac(ctxt_add), 2), 17.12)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt_add2), 2), 22.49)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt_sub), 2), 21.62)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt_sub2), 2), 16.25)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt_mult), 2), -43.58)
        self.assertEqual(round(pyfhel.decryptFrac(ctxt_mult2), 2), 60.43)

    def test_Pyfhel_4c_operations_batch_array(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        ctxti = pyfhel.encryptBatch([1, 2, 3, 4, 5, 6])
        ctxti2 = pyfhel.encryptArray(np.array([-6, -5, -4, -3, -2, -1]))
        ptxti = pyfhel.encodeArray(np.array([12, 15, 18, 21, 24, 27]))

        ctxt_add = pyfhel.add(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_add2 = pyfhel.add_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_sub = pyfhel.sub(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_sub2 = pyfhel.sub_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_mult = pyfhel.multiply(ctxti, ctxti2, in_new_ctxt=True)
        ctxt_mult2 = pyfhel.multiply_plain(ctxti, ptxti, in_new_ctxt=True)
        ctxt_rotate = pyfhel.rotate(ctxti, -2, in_new_ctxt=True)
        ctxt_rotate2 = pyfhel.rotate(ctxti, 2, in_new_ctxt=True)
        # self.ctxt_expon = self.pyfhel.power(self.ctxti, 3)
        # self.ctxt_expon2 = self.pyfhel.power(self.ctxti2, 3)
        # self.ctxt_polyEval = self.pyfhel.polyEval(self.ctxti, [1, 2, 1], in_new_ctxt=True)

        self.assertEqual(pyfhel.decryptBatch(ctxt_add)[:6], [-5, -3, -1, 1, 3, 5])
        self.assertEqual(pyfhel.decryptBatch(ctxt_add2)[:6], [13, 17, 21, 25, 29, 33])
        self.assertEqual(pyfhel.decryptBatch(ctxt_sub)[:6], [7, 7, 7, 7, 7, 7])
        self.assertEqual(
            pyfhel.decryptBatch(ctxt_sub2)[:6], [-11, -13, -15, -17, -19, -21]
        )
        self.assertEqual(
            pyfhel.decryptBatch(ctxt_mult)[:6], [-6, -10, -12, -12, -10, -6]
        )
        self.assertEqual(
            pyfhel.decryptBatch(ctxt_mult2)[:6], [12, 30, 54, 84, 120, 162]
        )
        self.assertEqual(pyfhel.decryptBatch(ctxt_rotate)[:6], [0, 0, 1, 2, 3, 4])
        self.assertEqual(pyfhel.decryptBatch(ctxt_rotate2)[:6], [3, 4, 5, 6, 0, 0])

    def test_Pyfhel_5_IO_SAVE_RESTORE(self):
        pass

    def test_Pyfhel_5a_save_objects(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        # self.pyfhel.relinKeyGen(60)

        self.assertTrue(pyfhel.saveContext("context.pycon"))
        self.assertTrue(pyfhel.savepublicKey("public_k.pypk"))
        self.assertTrue(pyfhel.savesecretKey("secret_k.pysk"))
        # self.assertTrue(self.pyfhel.saverelinKey("relin_k.pyrlk"))
        self.assertTrue(pyfhel.saverotateKey("rotate_k.pyrok"))

    def test_Pyfhel_5b_restore_objects(self):
        pyfhel = Pyfhel()
        self.assertTrue(pyfhel.restoreContext("context.pycon"))
        self.assertTrue(pyfhel.restoresecretKey("secret_k.pysk"))
        self.assertTrue(pyfhel.restorepublicKey("public_k.pypk"))
        # self.assertTrue(self.pyfhel.restorerelinKey("relin_k.pyrlk"))
        self.assertTrue(pyfhel.restorerotateKey("rotate_k.pyrok"))
        os.remove("context.pycon")
        os.remove("secret_k.pysk")
        os.remove("public_k.pypk")
        os.remove("rotate_k.pyrok")

    def test_Pyfhel_5c_save_restore_all(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        pyfhel.relinKeyGen(60, 4)
        # save all keys into temporary directory
        tmp_dir = tempfile.TemporaryDirectory()
        pyfhel.saveContext(tmp_dir.name + "/context")
        pyfhel.savepublicKey(tmp_dir.name + "/pub.key")
        pyfhel.savesecretKey(tmp_dir.name + "/sec.key")
        pyfhel.saverelinKey(tmp_dir.name + "/relin.key")
        pyfhel.saverotateKey(tmp_dir.name + "/rotate.key")
        # restore all keys
        pyfhel2 = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel2.restoreContext(tmp_dir.name + "/context")
        pyfhel2.restorepublicKey(tmp_dir.name + "/pub.key")
        pyfhel2.restoresecretKey(tmp_dir.name + "/sec.key")
        pyfhel2.restorerelinKey(tmp_dir.name + "/relin.key")
        pyfhel2.restorerotateKey(tmp_dir.name + "/rotate.key")

        # test encryption decryption
        ctxt1 = pyfhel.encryptBatch([42])
        self.assertEqual(
            pyfhel2.decryptBatch(ctxt1)[0],
            42,
            "decrypting with restored keys should work",
        )
        try:
            pyfhel2.rotate(ctxt1, -1)
            self.assertEqual(
                pyfhel2.decryptBatch(ctxt1)[1],
                42,
                "decrypting with restored keys should work",
            )
        except Exception as err:
            self.fail("PyPtxt() creation failed unexpectedly: ", err)

        # test ciphertext storing
        ctxt2 = pyfhel.encryptInt(42)
        ctxt2.save(tmp_dir.name + "/ctxt2")

        ctxt_restored = PyCtxt()
        ctxt_restored.load(tmp_dir.name + "/ctxt2")
        self.assertEqual(
            pyfhel2.decryptInt(ctxt_restored), 42, "decrypting ciphertext should work"
        )

    def test_Pyfhel_5d_save_restore_int(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        pyfhel.relinKeyGen(60, 4)
        # encrypt something
        ctxt = pyfhel.encryptInt(42)
        # save to temporary file
        tmp = tempfile.NamedTemporaryFile()
        ctxt.save(tmp.name)
        # load from temporary file
        loaded = PyCtxt()
        loaded.load(tmp.name)
        self.assertEqual(pyfhel.decryptInt(loaded), 42)

    def test_Pyfhel_5d_save_restore_float(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        pyfhel.relinKeyGen(60, 4)
        # encrypt something
        ctxt = pyfhel.encryptFrac(3.125)
        # save to temporary file
        tmp = tempfile.NamedTemporaryFile()
        ctxt.save(tmp.name)
        # load from temporary file
        loaded = PyCtxt()
        loaded.load(tmp.name, "float")
        self.assertEqual(pyfhel.decryptFrac(loaded), 3.125)

    def test_Pyfhel_5d_save_restore_batch(self):
        pyfhel = Pyfhel()
        pyfhel.contextGen(p=1964769281, m=8192, base=2, sec=192, flagBatching=True)
        pyfhel.keyGen()
        pyfhel.rotateKeyGen(60)
        pyfhel.relinKeyGen(60, 4)
        # encrypt something
        ctxt = pyfhel.encryptBatch([1, 2, 3, 4])
        # save to temporary file
        tmp = tempfile.NamedTemporaryFile()
        ctxt.save(tmp.name)
        # load from temporary file
        loaded = PyCtxt()
        loaded.load(tmp.name, "batch")
        self.assertEqual(pyfhel.decryptBatch(loaded)[:4], [1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main(verbosity=2)
