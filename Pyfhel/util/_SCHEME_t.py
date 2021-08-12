from enum import Enum, auto
class SCHEME_t(Enum):
    """An Enum to define the encryption scheme type"""
    def __repr__(self):
        return '<%s.%s>' % (self.__class__.__name__, self.name)

    UNDEFINED = object()
    """Default value for non defined scheme."""

    BFV = object()
    """Integer encoding, used with encryptInt/decryptInt and encodeInt/decodeInt."""

    CKKS = object()
    """Fractional encoding, used with encryptFrac/decryptFrac and encodeFrac/decodeFrac."""

    # Aliases
    INTEGER = BFV
    FRACTIONAL = CKKS