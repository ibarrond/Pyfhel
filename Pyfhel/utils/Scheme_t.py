from enum import Enum
class Scheme_t(Enum):
    """An Enum to define the scheme type"""

    none=0x0
    """Default value of 0 for non defined scheme."""

    bfv=0x1
    """Integer encoding, used with encryptInt/decryptInt and encodeInt/decodeInt."""

    ckks=0x2
    """Fractional encoding, used with encryptFrac/decryptFrac and encodeFrac/decodeFrac."""

    bgv=0x3
    """Integer encoding, used with encryptBGV/decryptBGV and encodeBGV/decodeBGV."""