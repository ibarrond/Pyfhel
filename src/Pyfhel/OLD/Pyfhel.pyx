#
#   PYFHEL
#   --------------------------------------------------------------------
#   PYthon For HELib, it implements Afhel (built on top of HElib) with a
#   syntax for arithmetic operations similar to normal arithmetics, while
#   preserving the same keyGen-encryption-decryption from Afhel. Pyfhel
#   works with PyPtxt as plaintext class and PyCtxt as cyphertext class.
#   --------------------------------------------------------------------
#   Author: Alberto Ibarrondo
#   Date: 28/06/2018
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

# Import the Plaintext and Cyphertext classes for Python
from PyPtxt import PyPtxt
from PyCtxt import PyCtxt
from PyCtxt import PyCtxtLenError

cdef class Pyfhel:
    cdef Afhel *afhel               # The C++ methods are accessed via a pointer
    cdef long modulus               # p^r, plaintext/cyphertext space size


    # INIT & DESTRUCT
    def __cinit__(self):
        self.afhel = new Afhel()
    def __dealloc__(self):
        del self.afhel

    
    # ----------------------------- CRYPTOGRAPHY ------------------------------
    # KEY GENERATION using the Afhel::keyGen for simplicity
    def keyGen(self, run_params):
        cdef vector[long] gens;
        cdef vector[long] ords;
        for k in run_params["gens"]:
            gens.push_back(k)
        for k in run_params["ords"]:
            ords.push_back(k)
        self.afhel.keyGen( run_params["p"],  run_params["r"],
                           run_params["c"],  run_params["d"],
                           run_params["sec"],run_params["w"],
                           run_params["L"],  run_params["m"],
                           run_params["R"],  run_params["s"],
                             gens, ords)
        self.modulus = long(pow(run_params["p"], run_params["r"]))
    

    # ENCRYPTION encrypt a PyPtxt object into a PyCtxt object
    def encrypt(self, ptxt, fill=0):
        if not isinstance(ptxt, PyPtxt):
            raise TypeError("Pyfhel encrypt error: ptxt isnt't type PyPtxt")
        cdef vector[long] ptxtVect;
        numSlots = self.numSlots()
        if numSlots < ptxt.numSlots():
            raise ValueError("Pyfhel encrypt error: input list has more elements than number of plaintext slots")
        ctxt = PyCtxt(ptxt.getPyfhel(), ptxt.getPtxtLen())
        for elt in ptxt.getPtxtList():      # for each list of size numSlots in Ptxt
            ptxtVect.clear()
            eltLen = len(elt)
            for k in range(numSlots):       # fills the list with "fill" up to numSlots
                if k < eltLen:
                    ptxtVect.push_back(elt[k])
                else:
                    ptxtVect.push_back(fill)
                                            # encrypts the list and appends the key
            ctxt.appendID(self.afhel.encrypt(ptxtVect))
        return ctxt                         # returns the PyCtxt with all the appended keys


    # DECRYPT a PyCtxt object into a List of values
    def decrypt(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel decrypt error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))
        retList = []
        cdef vector[long] retVect
        ids = ctxt.getIDs()
        lens = ctxt.getLen()
        for i,l in zip(ids,lens):           # For each key in PyCtxt
            retPtxt = []
            retV = self.afhel.decrypt(i)    # Decrypt its Afhel Ctxt
            for k in range(l):
                retPtxt.append(retV[k])     # Append values 1 by 1 to final list
            retList.append(retPtxt)
        return retList                      # Return only the non-filler values


    # DUPLICATE a PyCtxt with all its parameters, useful to keep originals in ops
    def duplicate(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel set error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))
        ids = ctxt.getIDs()                 # Use same Pyfhel class and same #IDs
        new_ctxt = PyCtxt(ctxt.getPyfhel(), ctxt.getLen())
        for i in ids:                       # Loop over all IDs and append them
            new_ctxt.appendID(self.afhel.set(i))
        return new_ctxt                     # Return duplicated PyCtxt


    # ----------------------------- OPERATIONS --------------------------------
    # ADD two PyCtxt objects for each ID in both
    def add(self, ctxt1, ctxt2, neg=False):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel addCtxt error: ctxt1 must be of type PyCtxt instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel addCtxt error: ctxt2 must be of type PyCtxt instead of type " + str(type(ctxt2)))

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
            raise TypeError("Pyfhel multiplyBy error: ctxt1 must be of type PyCtxt instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt2 must be of type PyCtxt instead of type " + str(type(ctxt2)))
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::mult to * each pair of Ctxts by IDs
            self.afhel.mult(ids1[i],ids2[i])


    # MULTIPLY 3 PyCtxt objects for each ID in both
    def mult3(self, ctxt1, ctxt2, ctxt3):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt1 must be of type PyCtxt instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt2 must be of type PyCtxt instead of type " + str(type(ctxt2)))
        if not isinstance(ctxt3, PyCtxt):
            raise TypeError("Pyfhel multiplyBy error: ctxt3 must be of type PyCtxt instead of type " + str(type(ctxt3)))    
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        ids3 = ctxt3.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        if n_ids != len(ids3):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::mult to * each pair of Ctxts by IDs
            self.afhel.mult3(ids1[i],ids2[i], ids3[i])




    # SCALAR PRODuct between two PyCtxt objects for each ID in both
    def scalarProd(self, ctxt1, ctxt2):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel scalarProd error: ctxt1 must be of type PyCtxt instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel scalarProd error: ctxt2 must be of type PyCtxt instead of type " + str(type(ctxt2)))
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::scalarProd to compute each pair of Ctxts by IDs
            self.afhel.scalarProd(ids1[i],ids2[i], 0)
            

    # SQUARE each cyphertext inside PyCtxt ctxt for each ID in it
    def square(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel square error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.square(ids[i])




    # CUMSUM Cumulative sum over all the values in the cyphertext
    def cumSum(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel cube error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.cumSum(ids[i])




    # CUBE each cyphertext inside PyCtxt ctxt for each ID in it
    def cube(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel cube error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.cube(ids[i])


    # NEGATE each cyphertext inside PyCtxt ctxt for each ID in it
    def negate(self, ctxt):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel negate error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.negate(ids[i])


    # COMPARE two PyCtxt objects for each ID in both
    def equalsTo(self, ctxt1, ctxt2):
        if not isinstance(ctxt1, PyCtxt):
            raise TypeError("Pyfhel equalsTo error: ctxt1 must be of type PyCtxt instead of type " + str(type(ctxt1)))
        if not isinstance(ctxt2, PyCtxt):
            raise TypeError("Pyfhel equalsTo error: ctxt2 must be of type PyCtxt instead of type " + str(type(ctxt2)))
        ids1 = ctxt1.getIDs()
        ids2 = ctxt2.getIDs()
        n_ids = len(ids1)
        comparison = []
        if n_ids != len(ids2):              # They must have the same # of IDs
            raise PyCtxtLenError()
        for i in range(n_ids):              # Use Afhel::equalsTo to * each pair of Ctxts by IDs
            comparison.append(self.afhel.mult(ids1[i],ids2[i]))
        return comparison


    # ROTATE each cyphertext inside PyCtxt ctxt for each ID in it
    def rotate(self, ctxt, c):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel rotate error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.rotate(ids[i], c)


    # SHIFT each cyphertext inside PyCtxt ctxt for each ID in it
    def shift(self, ctxt, c):
        if not isinstance(ctxt, PyCtxt):
            raise TypeError("Pyfhel rotate error: ctxt must be of type PyCtxt instead of type " + str(type(ctxt)))

        ids = ctxt.getIDs()
        n_ids = len(ids)

        for i in range(n_ids):
            self.afhel.shift(ids[i], c)



    # ----------------------------------- I/O ---------------------------------

    # SAVE ENVIRONMENT
    # Saves the environment into a .aenv file
    def saveEnv(self, fileName):
        if not isinstance(fileName, str):
            raise TypeError("Pyfhel saveEnv error: fileName must be of type str instead of type " + str(type(fileName)))
        self.afhel.saveEnv(fileName)
        return 


    # RESTORE ENVIRONMENT
    # Restores the environment from a .aenv file
    def restoreEnv(self, fileName):
        if not isinstance(fileName, str):
            raise TypeError("Pyfhel saveEnv error: fileName must be of type str instead of type " + str(type(fileName)))
        self.afhel.restoreEnv(fileName)
        self.modulus = long(pow(self.afhel.getP(), self.afhel.getR()))
        return

    #--------------------------------- AUXILIARY ------------------------------
    def numSlots(self):
        return self.afhel.numSlots()
    def getModulus(self):
        return self.modulus
    def delete(self, ctxt):
        for i in ctxt.getIDs():
            self.afhel.erase(i)
