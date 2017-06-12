from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool
		
cdef extern from "../../Afhel.h":
    cdef cppclass Afhel:
        Afhel() except +
        void keyGen(long p, long r, long c, long d, long sec, long w,
            long L, long m, long R, long s,
            const vector[long]& gens,
            const vector[long]& ords) except +
        string set(string key) except +
        string encrypt(vector[long] ptxt_vect) except +
        vector[long] decrypt(string key) except +

        void add(string k1, string k2, bool negative) except +
        void mult(string k1, string other_key) except +
        void scalarProd(string k1, string k2) except +
        void square(string k1) except +

        long numSlots() except +
        void erase(string key) except +

from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
from PyCtxt import PyCtxtLenError
cdef class PyHE:
    cdef Afhel *thisptr
    cdef long modulus

    def __cinit__(self):
        self.thisptr = new Afhel()
    def __dealloc__(self):
        del self.thisptr

    ########################################################################

    def keyGen(self, run_params):
        cdef vector[long] gens;
        cdef vector[long] ords;

        for elt in run_params["gens"]:
            gens.push_back(elt)

        for elt in run_params["ords"]:
            ords.push_back(elt)

        self.thisptr.keyGen( run_params["p"],
                             run_params["r"],
                             run_params["c"],
                             run_params["d"],
                             run_params["sec"],
                             run_params["w"],
                             run_params["L"],
                             run_params["m"],
                             run_params["R"],
                             run_params["s"],
                             gens, ords)

        self.modulus = run_params["p"]

    # for each list of size numSlots in PyPtxt object encrypt the list
    # and then append the key to a PyCtxt object
    def encrypt(self, ptxt, fill=0):
        if not isinstance(ptxt, PyPtxt):
            raise TypeError("encrypt error ptxt wasn't of type PyPtxt")

        cdef vector[long] ptxtVect;
        numSlots = self.numSlots()
        ptxtLen = ptxt.numSlots()
        if numSlots < ptxtLen:
            raise ValueError("PyHE encrypt error: input list has more "
                             "elements than number of plaintext slots")

        ctxt = PyCtxt(ptxt.getPyHE(), ptxt.getPtxtLen())

        for elt in ptxt.getPtxtList():
            ptxtVect.clear()

            eltLen = len(elt)
            for i in range(numSlots):
                if i < eltLen:
                    ptxtVect.push_back(elt[i])
                else:
                    ptxtVect.push_back(fill)

            ctxt.appendKey(self.thisptr.encrypt(ptxtVect))

        return ctxt

    # for each key in the PyCtxt object decrypt the Ctxt corresponding to that
    # key. Then concatenate all the lists together to create a single list.
    # Finally slice the list to be the same size as the original list that
    # this PyCtxt encrypted.
    def decrypt(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE decrypt error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))

        retList = []
        cdef vector[long] retVect
        keys = ctxt.getKeys()
        for key in keys:
            retVect = self.thisptr.decrypt(key)

            numSlots = self.numSlots()
            for i in range(numSlots):
                retList.append(retVect[i])

        return retList[:ctxt.getLen()]

    ########################################################################

    # Create a new PyCtxt object with the same initial parameters as ctxt
    # then copy all keys over and return new PyCtxt object.
    def duplicate(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE set error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))

        keys = ctxt.getKeys()
        new_ctxt = PyCtxt(ctxt.getPyHE(), ctxt.getLen())
        for key in keys:
            new_ctxt.appendKey(self.thisptr.set(key))

        return new_ctxt

    # Perform add for PyCtxt ctxt to PyCtxt otherCtxt for each key in both
    def add(self, ctxt, otherCtxt, neg=False):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE addCtxt error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))
        if not isinstance(otherCtxt, PyCtxt):
            raise TypeError("PyHE addCtxt error: otherCtxt must be of "
                            "type PyCtxt instead of type " +
                            str(type(otherCtxt)))

        keys = ctxt.getKeys()
        otherKeys = otherCtxt.getKeys()

        if len(keys) != len(otherKeys):
            raise PyCtxtLenError()

        numKeys = len(keys)
        for i in range(numKeys):
            self.thisptr.add(keys[i], otherKeys[i], neg)

    # Perform mult for PyCtxt ctxt to PyCtxt otherCtxt for each key in both
    def mult(self, ctxt, otherCtxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE multiplyBy error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))
        if not isinstance(otherCtxt, PyCtxt):
            raise TypeError("PyHE multiplyBy error: otherCtxt must be of "
                            "type PyCtxt instead of type " +
                            str(type(otherCtxt)))

        keys = ctxt.getKeys()
        otherKeys = otherCtxt.getKeys()

        if len(keys) != len(otherKeys):
            raise PyCtxtLenError()

        numKeys = len(keys)
        for i in range(numKeys):
            self.thisptr.mult(keys[i], otherKeys[i])

    # Perform mult for PyCtxt ctxt to PyCtxt otherCtxt for each key in both
    def scalarProd(self, ctxt, otherCtxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE multiplyBy error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))
        if not isinstance(otherCtxt, PyCtxt):
            raise TypeError("PyHE multiplyBy error: otherCtxt must be of "
                            "type PyCtxt instead of type " +
                            str(type(otherCtxt)))

        keys = ctxt.getKeys()
        otherKeys = otherCtxt.getKeys()

        if len(keys) != len(otherKeys):
            raise PyCtxtLenError()

        numKeys = len(keys)
        for i in range(numKeys):
            self.thisptr.scalarProd(keys[i], otherKeys[i])

    # Perform square for PyCtxt ctxt for each key in it
    def square(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("PyHE square error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))

        keys = ctxt.getKeys()
        numKeys = len(keys)

        for i in range(numKeys):
            self.thisptr.square(keys[i])

    ########################################################################

    # Helper Functions

    def numSlots(self):
        return self.thisptr.numSlots()
    def getModulus(self):
        return self.modulus
    def delete(self, ctxt):
        keys = ctxt.getKeys()

        for key in keys:
            self.thisptr.erase(key)
