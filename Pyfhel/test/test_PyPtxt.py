import pytest
import numpy as np
from Pyfhel import Pyfhel, PyPtxt
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

@pytest.fixture(scope="function")
def input_one(HE):
    return 1 if HE.scheme==Scheme_t.bfv else 1.

@pytest.fixture(scope="function")
def input_zero(HE):
    return 0 if HE.scheme==Scheme_t.bfv else 0.

################################################################################
#                             COVERAGE TESTS                                   #
################################################################################

class TestPyPtxt:
    def test_PyPtxt_creation(self, HE, input_one):
        # CONSTRUCTORS
        # Copy constructor
        p1 = HE.encode(input_one)
        p2 = PyPtxt(copy_ptxt=p1)
        del p1
        assert np.round(HE.decode(p2)[0])==1
        # Empty constructor
        p3 = PyPtxt(scheme=HE.scheme.name)
        assert p3.scheme == HE.scheme, "Wrong initialized scheme"
        # File-reading constructor without scheme --> exception
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            p4 = PyPtxt(fileName="fakeptxt.PyPtxt")
        # Byte-reading constructor without scheme --> exception
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            p4 = PyPtxt(bytestring=b"fakectxtcontent")

    def test_PyPtxt_properties(self, HE, input_one, input_zero):
        p = HE.encode(input_one)
        # PROPERTIES
        # Scheme
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            p.scheme = {"a wrong type of object": "woops!"}
        del p.scheme
        assert p.scheme == Scheme_t.none
        p.scheme = HE.scheme
        assert p.scheme == HE.scheme
        # Mod Level
        p.mod_level = 1
        del p.mod_level
        assert p.mod_level == 0
        # Pyfhel
        with pytest.raises(TypeError, match=".*<Pyfhel ERROR>.*") as e_info:
            p._pyfhel = "a wrong type of object"
        p._pyfhel = Pyfhel()
        p._pyfhel = HE
        assert id(p._pyfhel)==id(HE)
        # Scale
        p.scale = 1
        assert p.scale == 1
        # is_zero
        assert p.is_zero()==False
        p2 = HE.encode(input_zero)
        assert p2.is_zero()==True

    @pytest.mark.filterwarnings('ignore::pytest.PytestUnraisableExceptionWarning')
    def test_PyPtxt_save_load(self, HE, input_one, tmp_path):
        # Saving with empty pyfhel should raise an error --> Pytest cannot capture it, raises a warning instead
        p = PyPtxt()
        with pytest.raises(ValueError, match=".*<Pyfhel ERROR>.*") as e_info:
            bts = p.to_bytes()
        # with pytest.warns(UnraisableExceptionWarning):
        p.save("dummy.file") # Cannot capture warning??
        # File loading with custom scheme should override HE's scheme
        p = HE.encode(input_one)
        p.save(str(tmp_path / "p1"))
        p.load(str(tmp_path / "p1"), scheme=Scheme_t.none)
        assert p.scheme == Scheme_t.none
        # Byte deserializing with custom scheme should override HE's scheme
        p = HE.encode(input_one)
        bts = p.to_bytes()
        p.from_bytes(bts, scheme=Scheme_t.none)
        assert p.scheme == Scheme_t.none
        # Loading without pyfhel should raise an error
        p = PyPtxt()
        # with pytest.warns(UnraisableExceptionWarning):
        p.from_bytes(b"dummy")  # TODO: capture warning as error??
        # with pytest.warns(UnraisableExceptionWarning):
        p.load("dummy.file")    # TODO: capture warning as error??
    
    def test_PyPtxt_encode(self, HE, input_one, input_zero):
        p = HE.encode(input_one)
        p.encode(input_zero)
        if HE.scheme==Scheme_t.ckks:
            assert np.round(HE.decode(p)[0])==0
    
    def test_PyPtxt_cast_int_float(self, HE, input_one):
        p = HE.encode(input_one)
        if p.scheme == Scheme_t.bfv:
            assert int(p)==1
            with pytest.raises(RuntimeError, match=".*<Pyfhel ERROR>.*"):
                float(p)
        else:
            assert np.round(float(p))==1
            with pytest.raises(RuntimeError, match=".*<Pyfhel ERROR>.*"):
                int(p)