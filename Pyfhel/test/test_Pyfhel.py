import time
import pytest
import numpy as np
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
from Pyfhel.Pyfhel import _to_valid_file_str
from Pyfhel.utils import Scheme_t

################################################################################
#                                SETUP FIXTURES                                #
################################################################################
# The list of context parameters to be tested for each test
context_params_list_bfv = [
    {"scheme": "bfv",  "n": 16384, "t_bits": 30,   "sec":128,},
]
context_params_list_ckks = [
    {"scheme": "ckks", "n": 16384, "scale": 2**30, "qi_sizes": [60]+[30]*7+[60],},
    ]

# Pyfhel object setup
@pytest.fixture(scope="class", params=context_params_list_bfv)
def HE_bfv(request):
    HE = Pyfhel()
    HE.contextGen(**request.param)
    HE.keyGen()
    return HE
    
@pytest.fixture(scope="class", params=context_params_list_ckks)
def HE_ckks(request):
    HE = Pyfhel()
    HE.contextGen(**request.param)
    HE.keyGen()
    HE.relinKeyGen()
    HE.rotateKeyGen()
    return HE


################################################################################
#                             COVERAGE TESTS                                   #
################################################################################

class TestPyfhel:
    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_Pyfhel_creation(self):
        # CONSTRUCTORS
        # context gen --> should accept string as filename, but won't find it
        # with pytest.raises(BaseException,  match=".*<Pyfhel ERROR>.*") as e_info:
        he = Pyfhel(
            context_params = "fake_file.zip",
            pub_key_file = "fake_pubk_file.zip",
            sec_key_file = "fake_seck_file.zip")
        with pytest.raises(TypeError, match=".*must be a dictionary or a string.*"): # not 
            he = Pyfhel(context_params = 2)
        with pytest.raises(FileNotFoundError, match=".*<Pyfhel ERROR>.*") as e_info:
            _to_valid_file_str("fake_pubk_file.zip", True)
            # he = Pyfhel(pub_key_file = "fake_pubk_file.zip")
        with pytest.raises(FileNotFoundError, match=".*<Pyfhel ERROR>.*") as e_info:
            _to_valid_file_str("fake_seck_file.zip", True)
            # he = Pyfhel(sec_key_file = "fake_seck_file.zip")

    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_Pyfhel_properties(self, HE_ckks):
        # PROPERTIES
        # Scale
        he = Pyfhel()
        with pytest.raises(ValueError, match=".*scale must be a real number.*") as e_info:
            he.scale = "a wrong type of object"
        he.scale = 2**30
        assert he.scale == 2**30
        # total coeff bit count
        he.contextGen(scheme="bfv", n=16384, t_bits=30, sec=128)
        assert he.total_coeff_modulus_bit_count == 389   # checked in seal directly
        # noise level --> should capture raised error
        #with pytest.raises(ValueError, match=".*does not support noise level.*") as e_info:
        HE_ckks.noise_level(HE_ckks.encrypt(1.))

    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_Pyfhel_contextGen(self):
        # qi_sizes
        he = Pyfhel()
        he.contextGen(scheme="bfv", n=2**12, t=65537, sec=128, qi =[65537, 65543])
        with pytest.warns(match=".*without default scale.*"): # no default scale
            he.contextGen(scheme="ckks", n=2**12, qi_sizes=[60]+[30]*7+[60],)
        with pytest.warns(match=".*do not support rescaling.*"):
            he.contextGen(scheme="ckks", n=2**12, qi_sizes=[60]+[30]*7+[60], scale=2**31)

    def test_Pyfhel_encrypt(self, HE_ckks):
        # encryptComplex
        p = HE_ckks.encryptComplex(np.array([1+1j]))
        res = HE_ckks.decryptComplex(p)[0]
        assert np.round(np.real(res))==1
        assert np.round(np.imag(res))==1
        # encryptPtxt
        with pytest.raises(TypeError, match=".*PyPtxt Plaintext is empty.*"):
            HE_ckks.encryptPtxt(None)
        # vectorized 
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encryptAInt(np.array([[1,1],[1,1]],dtype=np.int64))
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encryptAFrac(np.array([[1., 1.], [1., 1.], ],dtype=np.float64))
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encryptAComplex(np.array([[1+1j,1j],[1-1j,1]]))
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encryptAPtxt(np.array([PyPtxt(), PyPtxt()], dtype=object))
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encrypt("wrong type")
        
    def test_Pyfhel_decrypt(self, HE_ckks):
        c = HE_ckks.encryptFrac(np.array([1.0],dtype=np.float64))
        with pytest.raises(RuntimeError, match=".*wrong scheme.*"):
            HE_ckks.decryptInt(c)
        c2 = PyCtxt(scheme='bfv')
        with pytest.raises(RuntimeError, match=".*wrong scheme.*"):
            HE_ckks.decryptFrac(c2)
        with pytest.raises(RuntimeError, match=".*wrong scheme.*"):
            HE_ckks.decryptComplex(c2)
        # vectorized 
        with pytest.raises(NotImplementedError, match=".*not implemented.*"):
            HE_ckks.decryptAInt(c)
        with pytest.raises(NotImplementedError, match=".*not implemented.*"):
            HE_ckks.decryptAFrac(c)
        with pytest.raises(NotImplementedError, match=".*not implemented.*"):
            HE_ckks.decryptAComplex(c)
        with pytest.raises(NotImplementedError, match=".*not implemented.*"):
            HE_ckks.decryptAPtxt(c)
        # full decode
        with pytest.raises(RuntimeError, match=".*wrong scheme.*"):
            c3 = PyCtxt()
            HE_ckks.decrypt(c3) # none scheme
    
    def test_Pyfhel_encode(self, HE_ckks):
        # vectorized 
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encodeAInt(np.array([[1]],dtype=np.int64))
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encodeAFrac(np.array([[1.]],dtype=np.float64))
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encodeAComplex(np.array([[1+1j]]))

        # 3d arrays not supported
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.encode(np.array([[[1.]]], dtype=np.float64)) 
        # non-numeric array not supported
        with pytest.raises(TypeError, match=".*cannot encrypt.*"):
            HE_ckks.encode(np.array([['hi', 'you']]))
        with pytest.raises(NotImplementedError, match=".*encryptAInt not implemented.*"):
            HE_ckks.encode(np.array([[1]],dtype=np.int64))
        with pytest.raises(NotImplementedError, match=".*encryptAFrac not implemented.*"):
            HE_ckks.encode(np.array([[1.]],dtype=np.float64))
        with pytest.raises(NotImplementedError, match=".*encryptAComplex not implemented.*"):
            HE_ckks.encode(np.array([[1+1j]]))

    def test_Pyfhel_decode(self, HE_ckks, HE_bfv):
        p = HE_ckks.encode(1)
        with pytest.raises(RuntimeError, match=".*scheme must be bfv.*"):
            HE_ckks.decodeInt(p)
        p = HE_bfv.encode(1)
        with pytest.raises(RuntimeError, match=".*scheme must be ckks.*"):
            HE_bfv.decodeFrac(p)
        with pytest.raises(RuntimeError, match=".*scheme must be ckks.*"):
            HE_bfv.decodeComplex(p)
        # Vectorized
        p_v = np.array([p],dtype=object)
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.decodeAInt(p_v)
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.decodeAFrac(p_v)
        with pytest.raises(NotImplementedError, match=".*<Pyfhel ERROR>.*"):
            HE_ckks.decodeAComplex(p_v)

        # scheme none
        del p.scheme
        with pytest.raises(RuntimeError, match=".*wrong scheme in PyPtxt.*"):
            HE_ckks.decode(p) 
        
    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_Pyfhel_ops(self, HE_ckks, HE_bfv):
        c_bfv = HE_bfv.encrypt(1)
        c_ckks = HE_ckks.encrypt(1.)
        p_ckks = HE_ckks.encode(1.)
        c_bfv = -c_bfv
        # Negation
        assert HE_bfv.decrypt(c_bfv)[0]==-1
        HE_bfv.negate(c_bfv, False)
        assert HE_bfv.decrypt(c_bfv)[0]==1
        # Addition
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv+c_ckks
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv+p_ckks
        # Cumul add
        with pytest.warns(match=".*rot_key empty.*"):
            HE_bfv_nokeys = Pyfhel()
            HE_bfv_nokeys.from_bytes_context(HE_bfv.to_bytes_context())
            c_cumul = HE_bfv_nokeys.cumul_add(c_bfv, in_new_ctxt=True)
            assert HE_bfv.decrypt(c_cumul)[0]!=HE_bfv.decrypt(c_bfv)[0]
        with pytest.raises(RuntimeError, match=".*n_elements.*"):
            HE_bfv_nokeys.cumul_add(c_bfv, n_elements=HE_bfv_nokeys.get_nSlots()+1)
        # Subtraction
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv-c_ckks
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv-p_ckks
        # Mult
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv*c_ckks
        with pytest.raises(RuntimeError, match=".*scheme type mistmatch.*"):
            c_bfv*p_ckks
        # Scalar prod
        c_sp = HE_ckks.scalar_prod(c_ckks, c_ckks,  in_new_ctxt=True)
        assert round(HE_ckks.decrypt(c_sp)[0])==HE_ckks.get_nSlots()
        assert round(HE_ckks.decrypt(c_ckks)[0])==1
        # rot
        with pytest.warns(match=".*rot_key empty.*"):
            c_bfv >>= 1
        # flip
        with pytest.warns(match=".*rot_key empty.*"):
            HE_bfv_nokeys = Pyfhel()
            HE_bfv_nokeys.from_bytes_context(HE_bfv.to_bytes_context())
            HE_bfv_nokeys.flip(c_bfv, in_new_ctxt=True) # Warning
            HE_bfv_nokeys.from_bytes_rotate_key(HE_bfv.to_bytes_rotate_key())
            cflip = HE_bfv_nokeys.flip(c_bfv + np.array([-1]), in_new_ctxt=True)
            assert HE_bfv.decrypt(cflip)[0]!=0
            HE_bfv_nokeys.flip(cflip)
            assert HE_bfv.decrypt(cflip)[0]==0
            
        # Relin
        with pytest.warns(match=".*relin_key empty.*"):
            c_bfv **= 4
        with pytest.warns(match=".*relin_key empty.*"):
            HE_bfv_nokeys = Pyfhel()
            HE_bfv_nokeys.from_bytes_context(HE_bfv.to_bytes_context())
            HE_bfv_nokeys.relinearize(c_bfv)
        # rescaling --> should capture an error
        # with pytest.raises(RuntimeError, match=".*Scheme must be CKKS.*"):
        HE_bfv.rescale_to_next(c_bfv)
        # mod switching
        with pytest.raises(TypeError, match=".*Expected PyCtxt or PyPtxt for mod switching.*"):
            HE_bfv.mod_switch_to_next(np.array([1]))

    def test_Pyfhel_align_mod_n_scale(self, HE_ckks, HE_bfv):
        # Small scale rounding
        c1 = HE_ckks.encrypt(1, scale=2**30+1)
        c2 = HE_ckks.encrypt(2, scale=2**30+2)
        HE_ckks.align_mod_n_scale(c1, c2)
        # not available rescalings
        with pytest.warns(match=".*Cannot align scales.*"):
            c1 = HE_ckks.encrypt(1, scale=2**30)
            c2 = HE_ckks.encrypt(2, scale=2**45)
            HE_ckks.align_mod_n_scale(c1, c2)

    def test_Pyfhel_auxiliary(self, HE_ckks, HE_bfv):
        # maxbitcount
        assert HE_bfv.maxBitCount(HE_bfv.n, HE_bfv.sec)==438
        # multdepth
        with pytest.raises(NotImplementedError):
            HE_bfv.multDepth()
        # batchEnabled
        assert HE_bfv.batchEnabled()==True
        assert HE_ckks.batchEnabled()==True
        # nSlots
        assert HE_bfv.get_nSlots()==HE_bfv.n
        assert HE_ckks.get_nSlots()==HE_ckks.n//2
        # get_scheme
        assert HE_bfv.get_scheme()==Scheme_t.bfv.value
        assert HE_ckks.get_scheme()==Scheme_t.ckks.value
    
    def test_Pyfhel_poly(self):
        pass
        # TODO: complete