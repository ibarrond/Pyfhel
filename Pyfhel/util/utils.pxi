from pathlib import Path

cpdef str _to_valid_file_str(fileName, bool check=False) except +:
    """_to_valid_file_str(fileName)
    
    Checks that the fileName is valid, and returns a str with the valid fileName.
    """
    if not isinstance(fileName, (str, Path)):
        raise TypeError("<Pyfhel ERROR> fileName must be of type str or Path.")
    if check:
        if not Path(fileName).is_file():
            raise FileNotFoundError(f"<Pyfhel ERROR> File {str(fileName)} not found.")
    return str(fileName)

cpdef to_ENCODING_t(encoding) except +:
    """to_ENCODING_t(encoding)
    
    Turns `encoding` into an ENCODING_t.{INTEGER, FRACTIONAL, BATCH} enum.
    
    Arguments:
        encoding (str, type, int, ENCODING_t): One of the following:

            * (str): ('int', 'integer') for INTEGER encoding, ('float', 'double') for 
              FRACTIONAL encoding, ('array', 'batch', 'matrix') for BATCH encoding.

            * Python class: (int) for INTEGER encoding, (float) for FRACTIONAL encoding, 
                (list) for BATCH encoding.

            * (int): (1) for INTEGER encoding, (2) for FRACTIONAL encoding,
                (3) for BATCH encoding.

            * (ENCODING_t) Enum (does nothing)

    Returns:
        ENCODING_t: INTEGER, FRACTIONAL or BATCH encoding.
    """
    if type(encoding) is unicode or isinstance(encoding, unicode):
        # encoding is a string. Casting it to str just in case.
        encoding = unicode(encoding)
        if encoding.lower()[0] == 'i':
            return ENCODING_t.INTEGER
        elif encoding.lower()[0] in 'fd':
            return ENCODING_t.FRACTIONAL
        elif encoding.lower()[0] in 'abm':
            return ENCODING_t.BATCH

    elif type(encoding) is type:
        if encoding is int:
            return ENCODING_t.INTEGER
        elif encoding is float:
            return ENCODING_t.FRACTIONAL
        if encoding is list:
            return ENCODING_t.BATCH
        
    elif isinstance(encoding, (int, float)) and\
         int(encoding) in (ENCODING_t.INTEGER.value,
                           ENCODING_t.FRACTIONAL.value,
                           ENCODING_t.BATCH.value):
            return ENCODING_t(int(encoding))
    
    elif isinstance(encoding, ENCODING_t):
        return encoding
    
    else:
        raise TypeError("<Pyfhel ERROR>: encoding unknown. Could not convert to ENCODING_t.")
