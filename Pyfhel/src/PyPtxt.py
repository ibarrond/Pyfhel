#    Copyright (C) 2015  Grant Frame
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from PyHE import PyHE

class PyPtxt:
    def __init__(self, ptxt, pyHe):
        if not isinstance(ptxt, list):
            raise TypeError("pyPtxt init error: ptxt must be of type list")
        if not isinstance(pyHe, PyHE):
            raise TypeError("pyPtxt init error: pyHE must be of type PyHE")

        from operator import mod
        self.__ptxt = [mod(elt, pyHe.getModulus()) for elt in ptxt]
        self.__pyHe = pyHe
        self.__length = len(ptxt)
        self.__numSlots = pyHe.numSlots()
        n = max(1, self.__numSlots)
        self.__ptxtList = [ptxt[i:i + n] for i in range (0, self.__length, n)]
        return

    def numSlots(self):
        return self.__numSlots

    def numPtxt(self):
        return len(self.__ptxtList)

    def getPtxtList(self):
        return self.__ptxtList

    def getPtxt(self):
        return self.__ptxt

    def getPyHE(self):
        return self.__pyHe

    def getPtxtLen(self):
        return self.__length

    ########################################################################
    # OPERATOR OVERRIDE METHODS #

    #####     STANDARD OPERATORS     ######
    # '+' operator
    def __add__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '+' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))

        newPtxt  = PyPtxt(self.getPtxt(), self.getPyHE())

        newPtxt += other

        return newPtxt

    # '-' operator
    def __sub__(self, other):
        if not isinstance(other, PyPtxt):
            if not isinstance(other, (PyPtxt, int)):
                raise TypeError("PyPtxt '-' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))

        newPtxt = PyPtxt(self.getPtxt(), self.getPyHE())

        newPtxt -= other

        return newPtxt

    # '*' operator
    def __mul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))

        newPtxt = PyPtxt(self.getPtxt(), self.getPyHE())

        newPtxt *= other

        return newPtxt

    # '@' operator
    def __matmul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*' error: lhs must be of type PyPtxt or "
                            "int instead of " + str(type(other)))

        newPtxt = PyPtxt(self.getPtxt(), self.getPyHE())

        from operator import mul, mod
        if isinstance(other, PyPtxt):
            res = sum(list(map(mul, self.getPtxt(), other.getPtxt())))
                          
        else:
            constPtxt = [other for _ in range(self.__length)]

            res = sum(list(map(mul, self.getPtxt(), constPtxt)))

            del constPtxt

        return res

    # negation operator
    def __neg__(self):
        newPtxt = PyPtxt(self.getPtxt(), self.getPyHE())

        newPtxt *= -1

        return newPtxt


    #####     IN-PLACE OPERATORS     ######

    # '+=' operator
    def __iadd__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '+=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))

        from operator import add, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(add, self.getPtxt(), other.getPtxt()))],
                          self.getPyHE())
        else:
            constPtxt = [other for _ in range(self.__length)]

            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(add, self.getPtxt(), constPtxt))],
                          self.getPyHE())

            del constPtxt

        return self

    # '-=' operator
    def __isub__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '-=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))

        from operator import sub, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(sub, self.getPtxt(), other.getPtxt()))],
                          self.getPyHE())
        else:
            constPtxt = [other for _ in range(self.__length)]

            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(sub, self.getPtxt(), constPtxt))],
                          self.getPyHE())

            del constPtxt

        return self

    # '*=' operator
    def __imul__(self, other):
        if not isinstance(other, (PyPtxt, int)):
            raise TypeError("PyPtxt '*=' error: lhs must be of type PyPtxt "
                            "or int instead of type " + str(type(other)))

        from operator import mul, mod
        if isinstance(other, PyPtxt):
            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(mul, self.getPtxt(), other.getPtxt()))],
                          self.getPyHE())
        else:
            constPtxt = [other for _ in range(self.__length)]

            self = PyPtxt([mod(elt, self.__pyHe.getModulus())
                           for elt in
                           list(map(mul, self.getPtxt(), constPtxt))],
                          self.getPyHE())

            del constPtxt

        return self

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
