cpdef enum class SCHEME_t:
    """An Enum to define the encryption scheme type"""
    
    # Default value for non defined scheme.
    UNDEFINED
    
    # Integer encoding, used with encryptInt/decryptInt and encodeInt/decodeInt
    BFV
    
    # Fractional encoding, used with encryptFrac/decryptFrac and encodeFrac/decodeFrac.
    CKKS