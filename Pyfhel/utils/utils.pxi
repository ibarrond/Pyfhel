from pathlib import Path


@cython.wraparound(False)
@cython.boundscheck(False)
cpdef np.ndarray[dtype=np.int64_t, ndim=1] vec_to_array_i(vector[int64_t] vec):
    cdef np.ndarray[dtype=np.int64_t, ndim=1] arr = np.empty(vec.size(), dtype=np.int64)
    cdef int64_t i
    for i in range(vec.size()):
        arr[i]=vec[i]
    return arr

@cython.wraparound(False)
@cython.boundscheck(False)
cpdef np.ndarray[dtype=double, ndim=1] vec_to_array_f(vector[double] vec):
    cdef np.ndarray[dtype=double, ndim=1] arr = np.empty(vec.size(), dtype=np.float64)
    cdef int64_t i
    for i in range(vec.size()):
        arr[i]=vec[i]
    return arr

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

cdef inline double _get_valid_scale(int& scale_bits, double& scale, double& pyfhel_scale):
    """Choose a non-zero scale"""
    if scale_bits > 0:
        return 2**scale_bits
    elif scale > 0:
        return scale
    elif pyfhel_scale > 0:
        return pyfhel_scale
    else:
        raise ValueError("<Pyfhel Error> ckks scale must be non-zero.")

cdef inline void _write_cy_attributes(Pyfhel he, ostream& ostr):
    """Serializes the security level, the moduli qi and the scale of `he`"""
    ostr.write(<char*>&he._sec, sizeof(int))
    cdef size_t qi_len = he._qi.size() 
    ostr.write(<char*>&qi_len, sizeof(size_t))
    ostr.write(<char*>he._qi.data(), qi_len*sizeof(int))
    ostr.write(<char*>&he._scale, sizeof(double))

cdef inline void _read_cy_attributes(Pyfhel he, istream& istr):
    """Deserializes the security level, the moduli qi and the scale back to `he`"""
    istr.read(<char*>&he._sec, sizeof(int))
    cdef size_t qi_len
    istr.read(<char*>&qi_len, sizeof(size_t))
    he._qi = vector[int](qi_len)
    istr.read(<char*>he._qi.data(), qi_len*sizeof(int))
    istr.read(<char*>&he._scale, sizeof(double))