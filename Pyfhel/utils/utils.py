
from pathlib import Path
import numpy as np

def _to_valid_file_str(fileName, check=False):
    """Checks that the fileName is valid, and returns a str with the valid fileName.
    """
    if not isinstance(fileName, (str, Path)):
        raise TypeError("<Pyfhel ERROR> fileName must be of type str or Path.")
    if check:
        if not Path(fileName).is_file():
            raise FileNotFoundError(f"<Pyfhel ERROR> File {str(fileName)} not found.")
    return str(fileName)

def modular_pow(base, exponent, modulus):
    """Modular exponentiation, from https://github.com/numpy/numpy/issues/8804"""
    return np.array([pow(int(b), exponent, modulus) for b in base])