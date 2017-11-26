#
#   PyCtxt
#   --------------------------------------------------------------------
#   PYthon CypherTeXT is a part of Pyfhel. PyCtxt implements the equivalent
#   to Ctxt class in Afhel (built on top of HElib) for cyphertexts, while
#   being able to hold several cyphertexts by their IDs and treat them as
#   a single one.
#   PyCtxt overrides +, -, * and @ with add, substract, mult and scalarProd
#   from Pyfhel.
#   --------------------------------------------------------------------
#   Author: Alberto Ibarrondo and Remy AUDA
#   Date: 23/11/2017  
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


# Import the other modules from Pyfhel
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
import numbers
import copy

class PyCtxt:
    
    # INITIALIZATION 
    def __init__(self, pyfhel, length):
        self.__ids = []
        if not isinstance(pyfhel, Pyfhel):
            raise TypeError("pyPtxt init error: pyfhel must be of type Pyfhel")
        if not isinstance(length, (list, int, long, float)):
            raise TypeError("pyPtxt init error: length not a number")

        self.__pyfhel = pyfhel
        self.__length = length
        return
    def __del__(self):
        self.__pyfhel.delete(self)
    def getIDs(self):
        return self.__ids
    def appendID(self, i):
        if not isinstance(i, str):
            raise TypeError("PyCtxt appendID error: ID must be a string")
        self.__ids.append(i)
    def getPyfhel(self):
        return self.__pyfhel
    def getLen(self):
        return self.__length
    

    # -------------------- OVERRIDE ARITHMETIC OPERATORS -------------------- #
    # Copy the ctxt and return the copy without modify the original one.
    def copy(self, ctxt):
        return self.__pyfhel.duplicate(ctxt)


    # ADD:
    # '+'operator -> Accepts both PyCtxt and Int
    def __add__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '+' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        newCtxt = self.copy(self)                        # Create new Ctxt for result
        if isinstance(other, PyCtxt):                   # Add directly if other is PyCtxt
            newCtxt += other
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))	# Create new PyCtxt from other if int
            newCtxt += constCtxt                        # Perform addition like in '+=' operator
            del constCtxt
        return newCtxt

    # '+=' operator
    def __iadd__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt ADD error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        if isinstance(other, PyCtxt):
            self.__pyfhel.add(self, other, False)       # Add directly if other is PyCtxt
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))	# Create new PyCtxt from other if int
            self.__pyfhel.add(self, constCtxt, False)   # Perform addition from Afhel::add
            del constCtxt
        return self




    # SUBSTRACT:
    # '-' operator
    def __sub__(self, other):
        if not isinstance(other, PyCtxt):
            if not isinstance(other, (PyCtxt, int)):
                raise TypeError("PyCtxt '-' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        #newCtxt = self.__pyfhel.set(self)
        newCtxt = self.copy(self)                        # Create new Ctxt for result
        if isinstance(other, PyCtxt):
            newCtxt -= other                            # Substract directly if other is PyCtxt
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))	# Crete new PyCtxt from other if int
            newCtxt -= constCtxt                        # Perform substraction from Afhel::add
            del constCtxt
        return newCtxt

    # '-=' operator
    def __isub__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '-=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        if isinstance(other, PyCtxt):
            self.__pyfhel.add(self, other, True)
        else:
            constCtxt = self.__pyfhel.encrypt(
                PyPtxt([other for _ in range(self.__length)],
                       self.__pyfhel))
            self.__pyfhel.add(self, constCtxt, True)
            del constCtxt
        return self



    # MULTIPLY:
    # '*' operator
    def __mul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        newCtxt = self.copy(self)                        # Create new Ctxt for result
        if isinstance(other, PyCtxt):
            newCtxt *= other
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            newCtxt *= constCtxt
            del constCtxt
        return newCtxt

    # '*=' operator
    def __imul__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        if isinstance(other, PyCtxt):
            self.__pyfhel.mult(self, other)
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            self.__pyfhel.mult(self, constCtxt)
            del constCtxt
        return self



    # SCALAR PRODUCT
    # '%' operator - scalarProd
    def __mod__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '%' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        newCtxt = self.copy(self)                        # Create new Ctxt for result
        if isinstance(other, PyCtxt):
            newCtxt %= other
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            newCtxt %= constCtxt
            del constCtxt
        return newCtxt

    # '%=' operator
    def __imod__(self, other):
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '%=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        if isinstance(other, PyCtxt):
            self.__pyfhel.scalarProd(self, other)
        else:
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            self.__pyfhel.scalarProd(self, constCtxt)
            del constCtxt
        return self



    # POWER
    # a ** b, b = 2|3 are the only ones supported
    def __pow__(self, other):
        if not isinstance(other, int):
            raise TypeError("PyCtxt '**=' error: lhs must be of type int instead of type " + str(type(other)))
        newCtxt = self.copy(self)                        # Create new Ctxt for result
        if(other==1):
            #Do nothing.
            newCtxt = newCtxt
        elif(other==2):
            self.__pyfhel.square(newCtxt)
        elif(other==3):
            self.__pyfhel.cube(newCtxt)
        else:
            raise ValueError("Pyfhel only supports square (2) and cube (3) exponents")
        return newCtxt

    # a **= b, b = 2|3 are the only ones supported
    def __ipow__(self, other):
        if not isinstance(other, int):
            raise TypeError("PyCtxt '**=' error: lhs must be of type int instead of type " + str(type(other)))
        if(other==1):
            #Do nothing.
            self = self
        elif(other==2):
            self.__pyfhel.square(self)
        elif(other==3):
            self.__pyfhel.cube(self)
        else:
            raise ValueError("Pyfhel only supports square (2) and cube (3) exponents")
        return self



    # CUMULATIVE SUM
    # '~' operator, total added value in all positions of the vector
    def __invert__(self):
        self.__pyfhel.cumSum(self)
        return self



    # SHIFT
    # 'lshift' operator
    def __lshift__(self, c):
        if not isinstance(c, numbers.Number):
            raise TypeError("c '*' error: it must be of type number instead of " + str(type(c)))
        self.__pyfhel.shift(self, c)
        return self

    # '<<=' operator
    def __ilshift__(self, c):
        if not isinstance(c, numbers.Number):
            raise TypeError("c '*' error: it must be of type number instead of " + str(type(c)))
        self.__pyfhel.shift(self,c)    
        return self

#-----------------------------Class Methods------------------------------



    """@Description:
    #The methode 

    #@param: The method takes a mandatory parameter:
    #-param1: The list of coefficients 
    """
    def polynomialMult(self, coefficients=[], *args):

        """Verifications on the type of the arguments given"""
        #If coefficients is not a list, we throw an error.
        if not isinstance(coefficients, list):
                raise TypeError("PyCtxt '-' error: coefficients must be of type list instead of " + str(type(coefficients)))
        #Otherwise, if coefficients is a list...
        elif isinstance(coefficients, list):
                #We verify if each items in the list coefficients are all of type PyCtxt. If not, we throw an error.
                if not all(isinstance(item, PyCtxt) for item in coefficients):
                       raise TypeError("PyCtxt '-' error: the coefficients must be of type PyCtxt instead of " + str(type(coefficients)))

        """Verifications on the lenght of the encrypted vectors."""
        #The lenght of each coefficients must be equal to the lenght of the X vector of the polynome P(X).
        for i, a in enumerate(coefficients):
                    if not self.getLen() == a.getLen():
                           print("\n")
                           print("Ciphertexts coefficients and the Ciphertexts X of the polynome P(X) have mismatched lengths.")
                           raise PyCtxtLenError()
        
        """Verifications on the degree of the polynome given."""
        #Define the number of coefficients of the polynome ie the degree of the polynome.
        n = len(coefficients)
        if n == 0:
           raise ValueError("No coefficients have been given.")
        #If we have more than 4 coefficients, it means that the degree of the polynome is greater than 4. And currently, Pyfhel only supports square and cube exponents.
        if n > 4:
           raise ValueError("Pyfhel only supports square (2) and cube (3) exponents.")

        """Perform the polynomial computations."""
        calc = self.copy(coefficients[0])
        for i, a in enumerate(coefficients):
                 if i != 0:
                     calc += (a*self)**i
        return calc   



class PyCtxtLenError(Exception):
    def __init__(self):
        self.message = "Ciphertexts have mismatched lengths."
