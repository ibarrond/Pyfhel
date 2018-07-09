cdef extern from "<iostream>" namespace "std":
    cdef cppclass ostream:
        ostream& write(const char*, int) except +
    cdef cppclass istream:
        istream& read(char*, int) except +


cdef extern from "<fstream>" namespace "std":
    cdef cppclass ofstream(ostream):
        # constructors
        ofstream(const char*) except +
    cdef cppclass ifstream(istream):
        # constructors
        ifstream(const char*) except +