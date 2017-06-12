from PyHE import PyHE
from PyPtxt import PyPtxt

class PyCtxt:
    def __init__(self, pyHe, length):
        self.__keys = []
        if not isinstance(pyHe, PyHE):
            raise TypeError("pyPtxt init error: pyHE must be of type PyHE")
        if not isinstance(length, (int, long, float)):
            raise TypeError("pyPtxt init error: length not a number")

        self.__pyHE = pyHe
        self.__length = length
        return
    def __del__(self):
        self.__pyHE.delete(self)
    def getKeys(self):
        return self.__keys
    def appendKey(self, key):
        if not isinstance(key, str):
            raise TypeError("PyCtxt appendKey error: key must be a string")

        self.__keys.append(key)
    def getPyHE(self):
        return self.__pyHE
    def getLen(self):
        return self.__length


    ########################################################################
    # OPERATOR OVERRIDE METHODS #

    #####     SET OPERATOR     ######
    # '=' operator
    def set(self):
        return self.__pyHE.set(self)

    #####     STANDARD OPERATORS     ######
    # '+' operator
    def __add__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '+' error: lhs must be of type PyCtxt or "
                            "int instead of " + str(type(other)))

        newCtxt = self.__pyHE.set(self)

        if isinstance(other, PyCtxt):
            newCtxt += other
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            newCtxt += constCtxt

            del constCtxt

        return newCtxt

    # '-' operator
    def __sub__(self, other):
        if not isinstance(other, PyCtxt):
            if not isinstance(other, (PyCtxt, int)):
                raise TypeError("PyCtxt '-' error: lhs must be of type PyCtxt or "
                            "int instead of " + str(type(other)))

        newCtxt = self.__pyHE.set(self)

        if isinstance(other, PyCtxt):
            newCtxt -= other
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            newCtxt -= constCtxt

            del constCtxt

        return newCtxt

    # '*' operator
    def __mul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*' error: lhs must be of type PyCtxt or "
                            "int instead of " + str(type(other)))

        newCtxt = self.__pyHE.set(self)

        if isinstance(other, PyCtxt):
            newCtxt *= other
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            newCtxt *= constCtxt

            del constCtxt

        return newCtxt


    # '@' operator - scalarProd
    def __matmul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*' error: lhs must be of type PyCtxt or "
                            "int instead of " + str(type(other)))

        newCtxt = self.__pyHE.set(self)

        if isinstance(other, PyCtxt):
            newCtxt @= other
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            newCtxt @= constCtxt

            del constCtxt

        return newCtxt



    #####     IN-PLACE OPERATORS     ######

    # '+=' operator
    def __iadd__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '+=' error: lhs must be of type PyCtxt "
                            "or int instead of type " + str(type(other)))

        if isinstance(other, PyCtxt):
            self.__pyHE.add(self, other, False)
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            self.__pyHE.addt(self, constCtxt, False)

            del constCtxt

        return self

    # '-=' operator
    def __isub__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '-=' error: lhs must be of type PyCtxt "
                            "or int instead of type " + str(type(other)))

        if isinstance(other, PyCtxt):
            self.__pyHE.add(self, other, True)
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            self.__pyHE.add(self, constCtxt, True)

            del constCtxt

        return self

    # '*=' operator
    def __imul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*=' error: lhs must be of type PyCtxt "
                            "or int instead of type " + str(type(other)))

        if isinstance(other, PyCtxt):
            self.__pyHE.mult(self, other)
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            self.__pyHE.mult(self, constCtxt)

            del constCtxt

        return self

    # '@=' operator
    def __imatmul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*=' error: lhs must be of type PyCtxt "
                            "or int instead of type " + str(type(other)))

        if isinstance(other, PyCtxt):
            self.__pyHE.scalarProd(self, other)
        else:
            constCtxt = self.__pyHE.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyHE))

            self.__pyHE.scalarProd(self, constCtxt)

            del constCtxt

        return self


class PyCtxtLenError(Exception):
    def __init__(self):
        self.message = "Ciphertexts have mismatched lengths."
