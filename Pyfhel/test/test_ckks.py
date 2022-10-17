import pytest
from Pyfhel import Pyfhel

################################################################################
#                                SETUP FIXTURES                                #
################################################################################
# The list of context parameters to be tested for each test
context_params_list = [
    {"scheme": "ckks", "n": 16384, "scale": 2**53, "qi_sizes": [60]+[53]*6+[60]}
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
#                             COVERAGE TESTS                                   #
################################################################################



################################################################################
#                            REGRESSION TESTS                                  #
################################################################################
@pytest.mark.parametrize("HE", context_params_list, indirect=True)
def test_issue128_ptxt_ctxt__mul__(HE):
    ctxt1 = HE.encrypt(42.0) * HE.encrypt(42.0)
    ptxt1 = HE.encode(42.0)

    fixed_ctxt1, fixed_ptxt1 = HE.align_mod_n_scale(ctxt1, ptxt1, only_mod=True)

    print(HE.decrypt(ctxt1))
    print(HE.decrypt(fixed_ctxt1))
    print(HE.decode(ptxt1))
    print(HE.decode(fixed_ptxt1))
    print(HE.decrypt(ctxt1 * ptxt1))
    print(HE.decrypt(fixed_ctxt1 * fixed_ptxt1))

    assert round(HE.decrypt(fixed_ctxt1 * fixed_ptxt1)[0]) == \
           round(HE.decrypt(ctxt1 * ptxt1)[0])             == \
           (42 * 42) * 42