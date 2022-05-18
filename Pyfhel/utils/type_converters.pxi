from Pyfhel.utils.Scheme_t import Scheme_t
from Pyfhel.utils.Backend_t import Backend_t

cpdef to_Scheme_t(object scheme):
    """Turns `scheme` into an scheme_t.{bfv, ckks} enum.
    
    Arguments:
        scheme (str, type, int, scheme_t): One of the following:

            * (str): ('int', 'integer', 'bfv') for bfv scheme, 
                     ('float', 'double', 'ckks') for ckks scheme.

            * Python class: (int) for bfv scheme, (float) for ckks scheme.

            * (int): (1) for bfv scheme, (2) for ckks scheme.

            * (scheme_t) Enum (does nothing)

    Returns:
        scheme_t: bfv or ckks.
    """
    if type(scheme) is type: scheme = scheme.__class__.__name__
    if type(scheme) is str:
        if scheme.lower() in ('int', 'integer', 'bfv'):     scheme = "bfv"
        elif scheme.lower() in ('float', 'double', 'ckks'): scheme = "ckks"
        return Scheme_t[scheme]
    elif isinstance(scheme, (int, float)):
        return Scheme_t(int(scheme))
    elif isinstance(scheme, Scheme_t):
        return scheme
    raise TypeError("<Pyfhel ERROR>: scheme unknown. Could not convert to Scheme_t.")


cpdef to_Backend_t(object backend):
    """Turns `backend` into a backend_t.{seal, palisade} enum.
    
    Arguments:
        backend (str, backend_t): One of the following:

            * (str): ('seal' | 'palisade') with uppercase variants.
            * (backend_t) Enum (does nothing)

    Returns:
        backend_t: seal or palisade.
    """
    if type(backend) is type: backend = backend.__class__.__name__
    if type(backend) is str:
        if backend.lower()   in ('seal'):     backend = "seal"
        elif backend.lower() in ('palisade'): backend = "palisade"
        return Backend_t[backend]
    elif isinstance(backend, (int, float)):
        return Backend_t(int(backend))
    elif isinstance(backend, Backend_t):
        return backend
    raise TypeError("<Pyfhel ERROR>: backend unknown. Could not convert to Backend_t.")
