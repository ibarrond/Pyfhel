# distutils: language = c++
#cython: language_level=3, boundscheck=False
# -------------------------------- CIMPORTS ------------------------------------
from libcpp.string cimport string

# ---------------------------- CYTHON DECLARATION ------------------------------

cdef extern from "<iostream>" namespace "std":
    cdef cppclass ostream:
        ostream& write(const char*, int) except +
    cdef cppclass istream:
        istream& read(char*, int) except +

cdef extern from "<fstream>" namespace "std":
    cdef cppclass ofstream(ostream):
        # constructors
        ofstream()except +
        ofstream(const char*) except +
        ofstream(const string&) except +
        void open(const char*) except +
        void open(const string&) except +
        void close() except +
    cdef cppclass ifstream(istream):
        # constructors
        ifstream()except +
        ifstream(const char*) except +
        ifstream(const string&) except +
        void open(const char&) except +
        void open(const string&) except +
        void close() except +

cdef extern from "<sstream>" namespace "std":
    cdef cppclass stringstream(istream):
        istringstream() except +
        istringstream(const char*) except +
        istringstream(const string&) except +
        stringstream& write(const char*, int) except +
    cdef cppclass ostringstream(ostream):
        ostringstream() except +
        string str() except +
