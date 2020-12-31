from enum import Enum
class ENCODING_t(Enum):
    """An Enum to define the encoding type"""

    UNDEFINED=0
    """Default value of 0 for non defined encoding."""

    INTEGER=1
    """Integer encoding, used with encryptInt/decryptInt and encodeInt/decodeInt."""

    FRACTIONAL=2
    """Fractional encoding, used with encryptFrac/decryptFrac and encodeFrac/decodeFrac."""

    BATCH=3
    """Batch encoding, used with encryptBatch/decryptBatch and encodeBatch/decodeBatch."""
