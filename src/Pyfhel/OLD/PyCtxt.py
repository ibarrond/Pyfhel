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


# Import the other modules from Pyfhel.
from Pyfhel import Pyfhel
from PyPtxt import PyPtxt
# Other imports useful for PyCtxt.
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
    """@Description:
    #The method copy allow to copy a PyCtxt object and to return the copy without modify the original one.

    #@param: The method takes a mandatory parameter: a PyCtxt.
    #-param1: The PyCtxt object to copy. 
    """
    def copy(self, ctxt):
        # Use the method duplicate from pyfhel.
        return self.__pyfhel.duplicate(ctxt)

    
    """@Description:
    #The operator + allow to add a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the sum. This operator doesn't modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to add. 
    """
    # ADD:
    # '+'operator -> Accepts both PyCtxt and Int
    def __add__(self, other):
        # If one wants to add a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '+' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        # Create new Ctxt for result
        newCtxt = self.copy(self) 
        # Add directly if other is PyCtxt                       
        if isinstance(other, PyCtxt):                   
            newCtxt += other
        #Otherwise, if one wants to add a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            # Perform addition like in '+=' operator	
            newCtxt += constCtxt                        
            del constCtxt
        return newCtxt

    """@Description:
    #The operator += allow to add a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the sum. This operator modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to add. 
    """
    # '+=' operator
    def __iadd__(self, other):
        # If one wants to add a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt ADD error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        # Add directly if other is PyCtxt
        if isinstance(other, PyCtxt):
            self.__pyfhel.add(self, other, False) 
        #Otherwise, if one wants to add a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.      
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))	
            # Perform addition from Afhel::add
            self.__pyfhel.add(self, constCtxt, False)   
            del constCtxt
        return self



    """@Description:
    #The operator - allow to substract a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the substract. This operator doesn't modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to substract. 
    """
    # SUBSTRACT:
    # '-' operator
    def __sub__(self, other):
        # If one wants to substract a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, PyCtxt):
            if not isinstance(other, (PyCtxt, int)):
                raise TypeError("PyCtxt '-' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        # Create new Ctxt for result.
        newCtxt = self.copy(self)   
        # Substract directly if other is PyCtxt.                     
        if isinstance(other, PyCtxt):
            newCtxt -= other
        #Otherwise, if one wants to substract a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.                                
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))	
            # Perform substraction from Afhel::add
            newCtxt -= constCtxt                        
            del constCtxt
        return newCtxt


    """@Description:
    #The operator -= allow to substract a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the substract. This operator modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to substract. 
    """
    # '-=' operator
    def __isub__(self, other):
        # If one wants to substract a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '-=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        # Substract directly if other is PyCtxt.                     
        if isinstance(other, PyCtxt):
            self.__pyfhel.add(self, other, True)
        #Otherwise, if one wants to substract a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            # Perform substraction from Afhel::add
            self.__pyfhel.add(self, constCtxt, True)
            del constCtxt
        return self


    """@Description:
    #The operator * allow to multiply a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the multiplication. This operator doesn't modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to multiply. 
    """
    # MULTIPLY:
    # '*' operator
    def __mul__(self, other):
        # If one wants to multiply a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        # Create new Ctxt for result.
        newCtxt = self.copy(self)                        
        # Multiply directly if other is PyCtxt.                     
        if isinstance(other, PyCtxt):
            newCtxt *= other
        #Otherwise, if one wants to multiply a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            newCtxt *= constCtxt
            del constCtxt
        return newCtxt


    """@Description:
    #The operator *= allow to multiply a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the multiplication. This operator modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to multiply. 
    """
    # '*=' operator
    def __imul__(self, other):
        # If one wants to multiply a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '*=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        # Multiply directly if other is PyCtxt.                     
        if isinstance(other, PyCtxt):
            self.__pyfhel.mult(self, other)
        #Otherwise, if one wants to multiply a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            # Perform multiplication from Afhel::mult
            self.__pyfhel.mult(self, constCtxt)
            del constCtxt
        return self


    """@Description:
    #The operator % allow to perform the scalar product between a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the scalar product (it will be an encrypted vector where all the elements will be the result of the scalar product). This operator doesn't modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to perform the scalar product.
    """
    # SCALAR PRODUCT
    # '%' operator - scalarProd
    def __mod__(self, other):
        # If one wants to perform scalar product on a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '%' error: lhs must be of type PyCtxt or int instead of " + str(type(other)))
        # Create new Ctxt for result.
        newCtxt = self.copy(self)  
        # Perform the scalar product directly if other is PyCtxt.                                          
        if isinstance(other, PyCtxt):
            newCtxt %= other
        #Otherwise, if one wants to perform scalar product on a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            # Perform scalar product.
            newCtxt %= constCtxt
            del constCtxt
        return newCtxt


    """@Description:
    #The operator %= allow to perform the scalar product between a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the scalar product (it will be an encrypted vector where all the elements will be the result of the scalar product). This operator modify the first operand.

    #@param: The method takes a mandatory parameter: a PyCtxt or an int.
    #-param1: The PyCtxt object or the int to perform the scalar product.
    """
    # '%=' operator
    def __imod__(self, other):
        # If one wants to perform scalar product on a PyCtxt with an object that is not either a PyCtxt or an int, we throw an error.
        if not isinstance(other, (PyCtxt, int)):
            raise TypeError("PyCtxt '%=' error: lhs must be of type PyCtxt or int instead of type " + str(type(other)))
        # Perform the scalar product directly if other is PyCtxt.                                          
        if isinstance(other, PyCtxt):
            self.__pyfhel.scalarProd(self, other)
        #Otherwise, if one wants to perform scalar product on a PyCtxt with an int, we have to create a vector of that int and then encrypted to transform it in PyCtxt.
        else:
            # Create new PyCtxt from other if int.
            constCtxt = self.__pyfhel.encrypt(PyPtxt([other for _ in range(self.__length)],self.__pyfhel))
            # Perform scalar product.
            self.__pyfhel.scalarProd(self, constCtxt)
            del constCtxt
        return self


    """@Description:
    #The operator ** allow to perform the power n of a PyCtxt object and return a PyCtxt object that contain the result. This operator doesn't modify the PyCtxt object which undergo the operation.

    #@param: The method takes a mandatory parameter: an int.
    #-param1: An int that represent the value of the power (thus, 2 means square, 3 means cube, etc...).
    """
    # POWER
    # a ** b
    def __pow__(self, other):
        # If one wants to perfor power n of a PyCtxt where n is not an int, we throw an error.
        if not isinstance(other, int):
            raise TypeError("PyCtxt '**=' error: lhs must be of type int instead of type " + str(type(other)))
        # Create new Ctxt for result.
        newCtxt = self.copy(self) 
        # If we want to perform our PyCtxt to power 0, we return an encrypted vector of 1.                       
        if(other==0):
            newCtxt = self.__pyfhel.encrypt(PyPtxt([1 for _ in range(self.__length)],self.__pyfhel))	# Create new PyCtxt of encrypted vector of 1. 
        # If we want to perform our PyCtxt to power 1, we return our PyCtxt.
        elif(other==1):
            #Do nothing.
            newCtxt = newCtxt
        # If we want to perform our PyCtxt to power 2, we return our PyCtxt square.
        elif(other==2):
            self.__pyfhel.square(newCtxt)
        # If we want to perform our PyCtxt to power 3, we return our PyCtxt cube.
        elif(other==3):
            self.__pyfhel.cube(newCtxt)
        # If we want to perform our PyCtxt to power n with n!=[0,1,2,3], we return our product(PyCtxt, n).
        else:
            # Create a copy of self.
            copySelf = self.copy(self)
            # Multiply the PyCtxt with himself to obtain PyCtxt*n.                        
            for i in range(other - 1):
                 newCtxt *= copySelf  
        return newCtxt


    """@Description:
    #The operator **= allow to perform the power n of a PyCtxt object and return a PyCtxt object that contain the result. This operator modify the PyCtxt object which undergo the operation.

    #@param: The method takes a mandatory parameter: an int.
    #-param1: An int that represent the value of the power (thus, 2 means square, 3 means cube, etc...).
    """
    # a **= b
    def __ipow__(self, other):
        # If one wants to perfor power n of a PyCtxt where n is not an int, we throw an error.
        if not isinstance(other, int):
            raise TypeError("PyCtxt '**=' error: lhs must be of type int instead of type " + str(type(other)))
        # If we want to perform our PyCtxt to power 0, we return an encrypted vector of 1.                       
        if(other==0):
            constCtxt = self.__pyfhel.encrypt(PyPtxt([1 for _ in range(self.__length)],self.__pyfhel))	# Create new PyCtxt of encrypted vector of 1.
            self = constCtxt
        # If we want to perform our PyCtxt to power 1, we return our PyCtxt.
        elif(other==1):
            #Do nothing.
            self = self
        # If we want to perform our PyCtxt to power 2, we return our PyCtxt square.
        elif(other==2):
            self.__pyfhel.square(self)
        # If we want to perform our PyCtxt to power 3, we return our PyCtxt cube.
        elif(other==3):
            self.__pyfhel.cube(self)
        # If we want to perform our PyCtxt to power n with n!=[0,1,2,3], we return our product(PyCtxt, n).
        else:
            # Create a copy of self.
            copySelf = self.copy(self) 
            # Multiply the PyCtxt with himself to obtain PyCtxt*n.                                              
            for i in range(other - 1):
                 self *= copySelf
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
    #The method polynomialMult allow to perform polyniomial computations on an encrypted vector PyCtxt. The polynome is of the form: P(x)= a0 + a1 * x + a2 * x**2 + ... + an * x**n.

    #@param: The method takes a mandatory parameter: a list of PyCtxt that represent the coefficients of the polynome.
    #-param1: A list of PyCtxt that represent the encrypted coefficients of the polynome. The first elements of the list must be a PyCtxt that represent a0. The second element must be a PyCtxt that represent a1, etc...
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
        #The lenght of each coefficient must be equal to the lenght of the X vector of the polynome P(X).
        for i, a in enumerate(coefficients):
                    if not self.getLen() == a.getLen():
                           print("\n")
                           print("Ciphertexts coefficients and the Ciphertexts X of the polynome P(X) have mismatched lengths.")
                           raise PyCtxtLenError()
        
        """Verifications on the degree of the polynome given. TODO: could be improve to support degree n."""
        #Define the number of coefficients of the polynome ie the degree of the polynome.
        n = len(coefficients)
        if n == 0:
           raise ValueError("No coefficients have been given.")
        #If we have more than 4 coefficients, it means that the degree of the polynome is greater than 4. And currently, Pyfhel only supports square and cube exponents.
        if n > 4:
           raise ValueError("Pyfhel only supports square (2) and cube (3) exponents.")

        """Perform the polynomial computations."""
        # Store the Pyctxt that represent a0 in a variable. 
        polynome_computation = coefficients[0]
        # Add to Pyctxt that represent a0, the other monomes.
        for i, a in enumerate(coefficients):
                 if i != 0:
                     polynome_computation += (a*self)**i
        return polynome_computation   



class PyCtxtLenError(Exception):
    def __init__(self):
        self.message = "Ciphertexts have mismatched lengths."
