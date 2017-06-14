#
#   PyPtxt
#   --------------------------------------------------------------------
#   PYthon PlainTeXT is a part of Pyfhel. Pytxt implements the equivalent
#   to Ptxt class in Afhel (built on top of HElib) for plaintexts, while
#   being able to hold several plaintexts in a list of lists and treat them 
#   as if they were a single one.
#   PyPtxt overrides +, -, * and @ with standard operations over its lists
#   --------------------------------------------------------------------
#   Author: Alberto Ibarrondo
#   Date: 14/06/2017  
#   --------------------------------------------------------------------
#   License: GNU GPL v3
#
#   PyCtxt is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   PyCtxt is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#   --------------------------------------------------------------------
#


from Pyfhel import Pyfhel

class PyPtxt:

    # INITIALIZATION -> Take a list or a list of lists and a Pyfhel object
    def __init__(self, ptxt, pyfhel):
        if not isinstance(ptxt, list):
            raise TypeError("pyPtxt init error: ptxt must be of type list")
        if not isinstance(pyfhel, Pyfhel):
            raise TypeError("pyPtxt init error: pyfhel must be of type Pyfhel")

        from operator import mod
        self.__ptxt = [mod(elt, pyfhel.getModulus()) for elt in ptxt]
        self.__pyfhel = pyfhel
        self.__length = len(ptxt)
        self.__numSlots = pyfhel.numSlots()
        n = max(1, self.__numSlots)
        self.__ptxtList = [ptxt[i:i + n] for i in range (0, self.__length, n)]
        return

    def numSlots(self):         return self.__numSlots
    def numPtxt(self):          return len(self.__ptxtList)
    def getPtxtList(self):      return self.__ptxtList
    def getPtxt(self):          return self.__ptxt
    def getPyfhel(self):        return self.__pyfhel
    def getPtxtLen(self):       return self.__length


    # -------------------- OVERRIDE ARITHMETIC OPERATORS -------------------- #

    # ADD:    
    # '+' operator
    def __add__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '+' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))
        newPtxt  = PyPtxt(self.getPtxt(), self.getPyfhel())
        newPtxt += other
        return newPtxt

    # '+=' operator
    def __iadd__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '+=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))
        from operator import add, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(add, self.getPtxt(), other.getPtxt()))],
                          self.getPyfhel())
        else:
            constPtxt = [other for _ in range(self.__length)]
            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(add, self.getPtxt(), constPtxt))],
                          self.getPyfhel())
            del constPtxt
        return self



    # SUBSTRACT:
    # '-' operator
    def __sub__(self, other):
        if not isinstance(other, PyPtxt):
            if not isinstance(other, (PyPtxt, int)):
                raise TypeError("PyPtxt '-' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))
        newPtxt = PyPtxt(self.getPtxt(), self.getPyfhel())
        newPtxt -= other
        return newPtxt

    # '-=' operator
    def __isub__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '-=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))
        from operator import sub, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(sub, self.getPtxt(), other.getPtxt()))],
                          self.getPyfhel())
        else:
            constPtxt = [other for _ in range(self.__length)]

            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(sub, self.getPtxt(), constPtxt))],
                          self.getPyfhel())
            del constPtxt
        return self



    # MULTIPLY:
    # '*' operator
    def __mul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))
        newPtxt = PyPtxt(self.getPtxt(), self.getPyfhel())
        newPtxt *= other
        return newPtxt
 
    # '*=' operator
    def __imul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))
        from operator import mul, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(mul, self.getPtxt(), other.getPtxt()))],
                          self.getPyfhel())
        else:
            constPtxt = [other for _ in range(self.__length)]
            self = PyPtxt([mod(elt, self.__pyfhel.getModulus())
                           for elt in
                           list(map(mul, self.getPtxt(), constPtxt))],
                          self.getPyfhel())
            del constPtxt
        return self


 
    # SCALAR PRODUCT:
    # '@' operator
    def __matmul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))
        newPtxt = PyPtxt(self.getPtxt(), self.getPyfhel())
        from operator import mul, mod
        if isinstance(other, PyPtxt):
            res = sum(list(map(mul, self.getPtxt(), other.getPtxt())))
        else:
            constPtxt = [other for _ in range(self.__length)]
            res = sum(list(map(mul, self.getPtxt(), constPtxt)))
            del constPtxt
        return res
    
    # '@=' operator
    def __imatmul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))
        newPtxt = PyPtxt(self.getPtxt(), self.getPyfhel())
        from operator import mul, mod
        if isinstance(other, PyPtxt):
            res = sum(list(map(mul, self.getPtxt(), other.getPtxt())))
        else:
            constPtxt = [other for _ in range(self.__length)]
            res = sum(list(map(mul, self.getPtxt(), constPtxt)))
            del constPtxt
        return res




    # -------------------- OVERRIDE LOGICAL OPERATORS -------------------- #
    # NEGATION:
    def __neg__(self):
        newPtxt = PyPtxt(self.getPtxt(), self.getPyfhel())
        newPtxt *= -1
        return newPtxt

    # '==' operator
    def __eq__(self, other):
        if not isinstance(other, PyPtxt):
            raise TypeError("PyPtxt '==' error: lhs must be of type PyPtxt "
                            "instead of type " + str(type(other)))
        return self.getPtxt() == other.getPtxt()

    # '!=' operator
    def __ne__(self, other):
        if not isinstance(other, PyPtxt):
            raise TypeError("PyPtxt '!=' error: lhs must be of type PyPtxt "
                            "instead of type " + str(type(other)))
        return not self == other
