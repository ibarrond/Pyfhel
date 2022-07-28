import time
import pytest
import numpy as np
from Pyfhel import Pyfhel, PyPtxt, PyCtxt
from Pyfhel.utils import Scheme_t, Backend_t, _to_valid_file_str, modular_pow

################################################################################
#                             COVERAGE TESTS                                   #
################################################################################

def test_utils_Scheme_t():
    none_scheme = Scheme_t.none
    assert none_scheme.value == 0x0
    assert none_scheme.name == "none"
    bfv_scheme = Scheme_t.bfv
    assert bfv_scheme.value == 0x1
    assert bfv_scheme.name == "bfv"
    ckks_scheme = Scheme_t.ckks
    assert ckks_scheme.value == 0x2
    assert ckks_scheme.name == "ckks"

def test_utils_Backend_t():
    none_backend = Backend_t.none
    assert none_backend.value == 0x0
    assert none_backend.name == "none"
    seal_backend = Backend_t.seal
    assert seal_backend.value == 0x1
    assert seal_backend.name == "seal"
    palisade_backend = Backend_t.palisade
    assert palisade_backend.value == 0x2
    assert palisade_backend.name == "palisade"

def test_utils_to_valid_file_str():
    with pytest.raises(FileNotFoundError, match=".*not found.*") as e_info:
        _to_valid_file_str("fake_seck_file.zip", True)
    with pytest.raises(TypeError, match=".*type str or Path.*") as e_info:
        _to_valid_file_str(1, True)
    assert _to_valid_file_str("pyproject.toml", True) == "pyproject.toml"

def test_utils_modular_pow():
    assert np.allclose(modular_pow([2,3], 3, 11), np.array([2,3])**3 % 11)
