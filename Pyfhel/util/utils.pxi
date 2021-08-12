from pathlib import Path

cpdef str _to_valid_file_str(fileName, bool check=False):
    """_to_valid_file_str(fileName)
    
    Checks that the fileName is valid, and returns a str with the valid fileName.
    """
    if not isinstance(fileName, (str, Path)):
        raise TypeError("<Pyfhel ERROR> fileName must be of type str or Path.")
    if check:
        if not Path(fileName).is_file():
            raise FileNotFoundError(f"<Pyfhel ERROR> File {str(fileName)} not found.")
    return str(fileName)

cpdef SCHEME_t to_SCHEME_t(object scheme):
    """Turns `scheme` into an SCHEME_t.{INTEGER, FRACTIONAL} enum.
    
    Arguments:
        scheme (str, type, int, SCHEME_t): One of the following:

            * (str): ('int', 'integer') for BFV scheme, ('float', 'double') for 
              CKKS scheme.

            * Python class: (int) for BFV scheme, (float) for CKKS scheme.

            * (int): (1) for BFV scheme, (2) for CKKS scheme.

            * (SCHEME_t) Enum (does nothing)

    Returns:
        SCHEME_t: BFV or CKKS.
    """
    if type(scheme) is unicode or isinstance(scheme, unicode):
        # scheme is a string. Casting it to str just in case.
        scheme = unicode(scheme)
        if scheme.lower() in ('int', 'integer'):
            return SCHEME_t.BFV
        elif scheme.lower() in ('float', 'double'):
            return SCHEME_t.CKKS

    elif type(scheme) is type:
        if scheme is int:
            return SCHEME_t.BFV
        elif scheme is float:
            return SCHEME_t.CKKS
        
    elif isinstance(scheme, (int, float)) and\
         int(scheme) in (SCHEME_t.BFV,
                           SCHEME_t.CKKS):
            return SCHEME_t(int(scheme))
    
    elif isinstance(scheme, SCHEME_t):
        return scheme
    
    raise TypeError("<Pyfhel ERROR>: scheme unknown. Could not convert to SCHEME_t.")