#
#   PYFHEL
#   --------------------------------------------------------------------
#   PYthon For HELib, it implements Afhel (built on top of HElib) with a
#   syntax for arithmetic operations similar to normal arithmetics, while
#   preserving the same keyGen-encryption-decryption from Afhel. Pyfhel
#   works with PyPtxt as plaintext class and PyCtxt as cyphertext class.
#   --------------------------------------------------------------------
#   Author: Alberto Ibarrondo
#   Date: 14/06/2017  
#   --------------------------------------------------------------------
#   License: GNU GPL v3
#
#   Pyfhel is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   Pyfhel is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#   --------------------------------------------------------------------
#

# Importing the required C++ types for the Afhel API: vector, string & bool
from libcpp.vector cimport vector
from libcpp.string cimport string
from libcpp cimport bool

# Using Ctypes to define the Afhel class
cdef extern from "../../Afhel/Afhel.h":
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

# Import the Plaintext and Cyphertext classes for Python
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
from PyCtxt import PyCtxtLenError

cdef class Pyfhel:
    cdef Afhel *afhel               # The C++ methods are accessed via a pointer
    cdef long modulus               # p^r, plaintext/cyphertext space size


    # INIT & DESTRUCT
    def __cinit__(self):        self.afhel = new Afhel()
    def __dealloc__(self):      del self.afhel


    # KEY GENERATION using the Afhel::keyGen for simplicity
    def keyGen(self, run_params):
        cdef vector[long] gens;
        cdef vector[long] ords;
        for k in run_params["gens"]:   gens.push_back(k)
        for k in run_params["ords"]:   ords.push_back(k)
        self.afhel.keyGen( run_params["p"],  run_params["r"],
                           run_params["c"],  run_params["d"],
                           run_params["sec"],run_params["w"],
                           run_params["L"],  run_params["m"],
                           run_params["R"],  run_params["s"],
                             gens, ords)
        self.modulus = int(pow(run_params["p"], run_params["r"]))
    

    # ENCRYPTION encrypt a PyPtxt object into a PyCtxt object
    def encrypt(self, ptxt, fill=0):
        if not isinstance(ptxt, PyPtxt):
            raise TypeError("encrypt error ptxt wasn't of type PyPtxt")
        cdef vector[long] ptxtVect;
        numSlots = self.numSlots()
        if numSlots < ptxt.numSlots():
            raise ValueError("Pyfhel encrypt error: input list has more "
                             "elements than number of plaintext slots")
        ctxt = PyCtxt(ptxt.getPyfhel(), ptxt.getPtxtLen())
        for elt in ptxt.getPtxtList():      # for each list of size numSlots in Ptxt
            ptxtVect.clear()
            eltLen = len(elt)
            for k in range(numSlots):       # fills the list with "fill" up to numSlots
                if k < eltLen:  ptxtVect.push_back(elt[k])
                else:           ptxtVect.push_back(fill)
                                            # encrypts the list and appends the key
            ctxt.appendID(self.afhel.encrypt(ptxtVect))
        return ctxt                         # returns the PyCtxt with all the appended keys


    # DECRYPT a PyCtxt object into a List of values
    def decrypt(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel decrypt error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))
        retList = []
        cdef vector[long] retVect
        ids = ctxt.getIDs()
        for i in ids:                       # For each key in PyCtxt
            retV = self.afhel.decrypt(i)    # Decrypt its Afhel Ctxt
            for k in range(self.numSlots()):
                retList.append(retV[k])     # Append values 1 by 1 to final list
        return retList[:ctxt.getLen()]      # Return only the non-filler values


    # DUPLICATE a PyCtxt with all its parameters, useful to keep originals in ops
    def duplicate(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel set error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))
        ids = ctxt.getIDs()                 # Use same Pyfhel class and same #IDs
        new_ctxt = PyCtxt(ctxt.getPyfhel(), ctxt.getLen())
        for i in ids:                       # Loop over all IDs and append them
            new_ctxt.appendID(self.afhel.set(i))
        return new_ctxt                     # Return duplicated PyCtxt


    # ADD two PyCtxt objects for each ID in both
    def add(self, ctxt1, ctxt2, neg=False):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel addCtxt error: ctxt1 must be of type PyCtxt "
                            "instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel addCtxt error: ctxt2 must be of "
                            "type PyCtxt instead of type " +
                            str(type(ctxt2)))

        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::add to + each pair of Ctxts by IDs
            self.afhel.add(ids1[i],ids2[i], neg)


    # MULTiply two PyCtxt objects for each ID in both
    def mult(self, ctxt1, ctxt2):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt1 must be of type PyCtxt "
                            "instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt2 must be of "
                            "type PyCtxt instead of type " +
                            str(type(ctxt2)))
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::mult to * each pair of Ctxts by IDs
            self.afhel.mult(ids1[i],ids2[i])


    # SCALAR PRODuct betweentwo PyCtxt objects for each ID in both
    def scalarProd(self, ctxt1, ctxt2):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt1 must be of type PyCtxt "
                            "instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt2 must be of "
                            "type PyCtxt instead of type " +
                            str(type(ctxt2)))
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::mult to * each pair of Ctxts by IDs
            self.afhel.mult(ids1[i],ids2[i])
            
    # SQUARE each cyphertext inside PyCtxt ctxt for each ID in it
    def square(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel square error: ctxt must be of type PyCtxt "
                            "instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.square(ids[i])



    #-------------------------------------------------------------------------#

    # AUXILIARY FUNCTIONS
    def numSlots(self):             return self.afhel.numSlots()
    def getModulus(self):           return self.modulus
    def delete(self, ctxt):
        for i in ctxt.getIDs():
            self.afhel.erase(i)
