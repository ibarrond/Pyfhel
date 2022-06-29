import pytest
from Pyfhel import Pyfhel

################################################################################
#                                SETUP FIXTURES                                #
################################################################################
# The list of context parameters to be tested for each test
context_params_list = [
    {"scheme": "ckks", "n": 16384, "scale": 2**30, "qi": [60]+[30]*7+[60]}
    ]

# Pyfhel object setup
@pytest.fixture
def HE(request):
    HE = Pyfhel()
    HE.contextGen(**request.param)
    HE.keyGen()
    HE.relinKeyGen()
    return HE

################################################################################
#                                  TESTS                                       #
################################################################################
@pytest.mark.parametrize("HE", context_params_list, indirect=True)
def test_issue128_ptxt_ctxt__mul__(HE):
    ctxt1 = HE.encrypt(42.0) * HE.encrypt(42.0)
    ptxt1 = HE.encode(42.0)

    fixed_ctxt1, fixed_ptxt1 = HE.align_mod_n_scale(ctxt1, ptxt1, only_mod=True)

    print(f"This works -> {fixed_ctxt1 * fixed_ptxt1}")
    # print(f"This DOES NOT work -> {ctxt1 * ptxt1}")