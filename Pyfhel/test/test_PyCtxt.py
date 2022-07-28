import pytest
import numpy as np
from Pyfhel import Pyfhel, PyCtxt
from Pyfhel.PyCtxt import cumsum
from Pyfhel.utils import Scheme_t

################################################################################
#                                SETUP FIXTURES                                #
################################################################################
# The list of context parameters to be tested for each test
context_params_list = [
    {"scheme": "bfv",  "n": 16384, "t_bits": 30,   "sec":128,},
    {"scheme": "ckks", "n": 16384, "scale": 2**30, "qi": [60]+[30]*7+[60],},
    ]

# Pyfhel object setup
@pytest.fixture(scope="class", params=context_params_list)
def HE(request):
    HE = Pyfhel()
    HE.contextGen(**request.param)
    HE.keyGen()
    HE.relinKeyGen()
    HE.rotateKeyGen()
    return HE


################################################################################
#                             COVERAGE TESTS                                   #
################################################################################

class TestPyCtxt:
    def test_PyCtxt_creation(self, HE):
        # CONSTRUCTORS
        # Copy constructor
        c1 = HE.encrypt(1)
        c2 = PyCtxt(copy_ctxt=c1)
        del c1
        assert np.round(HE.decrypt(c2)[0])==1
        # Empty constructor
        c3 = PyCtxt(scheme=HE.scheme.name)
        assert c3.scheme == HE.scheme, "Wrong initialized scheme"
        # File-reading constructor without scheme --> exception
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c4 = PyCtxt(fileName="fakectxt.pyctxt")
        # Byte-reading constructor without scheme --> exception
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c4 = PyCtxt(bytestring=b"fakectxtcontent")

    def test_PyCtxt_properties(self, HE):
        c = HE.encrypt(1)
        # PROPERTIES
        # Scheme
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c.scheme = {"a wrong type of object": "woops!"}
        del c.scheme
        assert c.scheme == Scheme_t.none
        assert "?" in c.__repr__() # --> When scheme is not known
        c.scheme = HE.scheme
        assert c.scheme == HE.scheme
        # Mod Level
        c.mod_level = 1
        del c.mod_level
        assert c.mod_level == 0
        # Pyfhel
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c._pyfhel = "a wrong type of object"
        c._pyfhel = Pyfhel()
        c._pyfhel = HE
        assert id(c._pyfhel)==id(HE)
        # Size
        assert c.size() == 2
        # Scale
        c.scale = 1
        assert c.scale == 1

    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_PyCtxt_save_load(self, HE, tmp_path):
        # Saving with empty pyfhel should raise an error --> Pytest cannot capture it, raises a warning instead
        c = PyCtxt()
        with pytest.raises(ValueError, match=".*<Pyfhel ERROR>.*") as e_info:
            bts = c.to_bytes()
        # with pytest.warns(UnraisableExceptionWarning):
        c.save("dummy.file") # Cannot capture warning??
        # File loading with custom scheme should override HE's scheme
        c = HE.encrypt(1)
        c.save(str(tmp_path / "c1"))
        c.load(str(tmp_path / "c1"), scheme=Scheme_t.none)
        assert c.scheme == Scheme_t.none
        # Byte deserializing with custom scheme should override HE's scheme
        c = HE.encrypt(1)
        bts = c.to_bytes()
        c.from_bytes(bts, scheme=Scheme_t.none)
        assert c.scheme == Scheme_t.none
        # Loading without pyfhel should raise an error
        c = PyCtxt()
        # with pytest.warns(UnraisableExceptionWarning):
        c.from_bytes(b"dummy")  # TODO: capture warning as error??
        # with pytest.warns(UnraisableExceptionWarning):
        c.load("dummy.file")    # TODO: capture warning as error??
    
    def test_PyCtxt_add(self, HE):
        c = HE.encrypt(1)
        # Wrong summand type
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            no_numeric_sumand = c + "1"
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c += "1"
        # Plaintext iadd
        c += 1
        assert np.round(HE.decrypt(c)[0])==2
    
    def test_PyCtxt_sub(self, HE):
        c1 = HE.encrypt(1)
        c2 = HE.encrypt(2)
        # Wrong input type
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c1 -= {"1"}
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c1 = c1 - "1" 
        # Plaintext & ciphertext isub 
        c1 -= 2
        c1 -= c2  # c1[0]=0
        assert np.round(HE.decrypt(c1)[0])==-3
    
    def test_PyCtxt_mul(self, HE):
        c = HE.encrypt(1)
        # Wrong factor type
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c *= {"1"}
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c = c * "1" 
        # Plaintext imul 
        c *= c
        c *= 1
        assert np.round(HE.decrypt(c)[0])==1

    def test_PyCtxt_truediv(self, HE):
        c1 = HE.encrypt(1)
        c2 = HE.encrypt(2)
        p = HE.encode(1)
        # Wrong summand type
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c1 /= {"2"}
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            c1 = c1 / c2  # Divison requires float/int/plaintext to get the inverse 
        # truediv
        c1 = c1 / 1
        c1 = c1 / p
        c1 /= 1
        c1 /= p
        assert np.round(HE.decrypt(c1)[0])==1
        # Wrong scheme
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            del c1.scheme     #  = Scheme_t.none
            c1 /= 1
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            del c1.scheme
            c1 = c1 / 1
             
    def test_PyCtxt_pow(self, HE):
        c = HE.encrypt(2)
        c **=2
        assert np.round(HE.decrypt(c)[0])==4
        # Exponentiate oly available in bfv
        if c._pyfhel.scheme == Scheme_t.bfv:
            with pytest.raises(ValueError, match=".*not enough relinearization keys.*") as e_info:
                c **= 3
                # TODO: make enough relin keys to make this work
                # assert np.round(HE.decrypt(c)[0])==64
        else: # ckks scheme raises an error
            with pytest.raises(RuntimeError, match=".*unsupported scheme.*") as e_info:
                c **= 3
    
    def test_PyCtxt_rotate(self, HE):
        c1 = HE.encrypt(1)
        c1 >>= 1
        c1 <<= 1
        assert np.round(HE.decrypt(c1)[0])==1
    
    def test_PyCtxt_io(self, HE):
        c = HE.encrypt(1)
        assert bytes(c) == c.to_bytes()
        # Cannot serialize without a pyfhel object
        with pytest.raises(ValueError, match=".*<Pyfhel ERROR>.*") as e_info:
            del c._pyfhel
            c.to_bytes()
        # c._pyfhel = HE
        # with pytest.raises(ValueError, match=".*<Pyfhel ERROR>.*") as e_info:
        #     del c._pyfhel
        #     c.save("dummy.file")
        # Cannot deserialize without pyfhel object
    
    def test_PyCtxt_encrypt(self, HE):
        c = HE.encrypt(1)
        c.encrypt(2)
        assert np.round(HE.decrypt(c)[0])==2
    
    def test_PyCtxt_encode_operand(self, HE):
        c = HE.encrypt(1)
        if c.scheme == Scheme_t.bfv:
            pass # Complex values not supported in bfv
        else:
            p = c.encode_operand([1+1j, 1j])  # Encode complex number
            c += p
            res = HE.decryptComplex(c)
            assert np.round(np.real(res[0]))==2
            assert np.round(np.imag(res[1]))==1
            
    def test_PyCtxt_cumsum(self, HE):
        cs = cumsum(np.array([HE.encrypt(1), HE.encrypt(2), HE.encrypt(3)]))
        assert np.round(HE.decrypt(cs)[0])==6