# Pyfhel

| **class Pyfhel** |               |
|-------------------------|---------------|
| **functions**           |               |
| _ init _                | Create an instance of Pyfhel |
| keyGen                 | Create the key used during the encryption. |
| encrypt                   | Encrypt a PyPtxt object into a PyCtxt object. |
| decrypt                   | Decrypt a PyCtxt object into a List of values. |
| duplicate                   | DUPLICATE a PyCtxt with all its parameters, useful to keep originals in ops. |
| add                   | ADD two PyCtxt objects for each ID in both. |
| mult                   | MULTiply two PyCtxt objects for each ID in both. |
| mult3                   | MULTIPLY 3 PyCtxt objects for each ID in both. |
| scalarProd                   | SCALAR PRODuct between two PyCtxt objects for each ID in both. |
| square                   | SQUARE each cyphertext inside PyCtxt ctxt for each ID in it. |
| cumSum                   | CUMSUM Cumulative sum over all the values in the cyphertext. |
| cube                   | CUBE each cyphertext inside PyCtxt ctxt for each ID in it. |
| negate                   | NEGATE each cyphertext inside PyCtxt ctxt for each ID in it. |
| equalsTo                   | COMPARE two PyCtxt objects for each ID in both. |
| rotate                   | ROTATE each cyphertext inside PyCtxt ctxt for each ID in it. |
| shift                   | SHIFT each cyphertext inside PyCtxt ctxt for each ID in it. |
| saveEnv                   | Saves the environment into a .aenv file. |
| restoreEnv                   | Restores the environment from a .aenv file. |



# PyCtxt

| **class PyCtxt** |               |
|-------------------------|---------------|
| **functions**           |               |
| _ init _                | Create an instance of PyCtxt |
| copy                 | @Description: The method copy allow to copy a PyCtxt object and to return the copy without modify the original one. @param: The method takes a mandatory parameter: a PyCtxt. -param1: The PyCtxt object to copy. |
| +                   | @Description: The operator + allow to add a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the sum. This operator doesn't modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to add. |
| +=                   | @Description: The operator += allow to add a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the sum. This operator modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to add.  |
| -                   | @Description: The operator - allow to substract a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the substract. This operator doesn't modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to substract.  |
| -=                   | @Description: The operator -= allow to substract a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the substract. This operator modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to substract.  |
| *                   | @Description: The operator * allow to multiply a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the multiplication. This operator doesn't modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to multiply.  |
| *=                   | @Description: The operator *= allow to multiply a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the multiplication. This operator modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to multiply. |
| %                   | @Description: The operator % allow to perform the scalar product between a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the scalar product (it will be an encrypted vector where all the elements will be the result of the scalar product). This operator doesn't modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to perform the scalar product. |
| %=                   | @Description: The operator %= allow to perform the scalar product between a PyCtxt object with an other PyCtxt object or an int and to return a PyCtxt object that contain the scalar product (it will be an encrypted vector where all the elements will be the result of the scalar product). This operator modify the first operand. @param: The method takes a mandatory parameter: a PyCtxt or an int. -param1: The PyCtxt object or the int to perform the scalar product. |
| \**                   | @Description: The operator \** allow to perform the power n of a PyCtxt object and return a PyCtxt object that contain the result. This operator doesn't modify the PyCtxt object which undergo the operation. @param: The method takes a mandatory parameter: an int. -param1: An int that represent the value of the power (thus, 2 means square, 3 means cube, etc...). |
| \**=                   | @Description: The operator \**= allow to perform the power n of a PyCtxt object and return a PyCtxt object that contain the result. This operator modify the PyCtxt object which undergo the operation. @param: The method takes a mandatory parameter: an int. -param1: An int that represent the value of the power (thus, 2 means square, 3 means cube, etc...). |
| ~                   | total added value in all positions of the vector. |
| 'lshift' operator                   | 'lshift' operator. |
| '<<=' operator                   | '<<=' operator. |
| polynomialMult                   | @Description: The method polynomialMult allow to perform polyniomial computations on an encrypted vector PyCtxt. The polynome is of the form: P(x)= a0 + a1 * x + a2 * x\**2 + ... + an * x\**n. @param: The method takes a mandatory parameter: a list of PyCtxt that represent the coefficients of the polynome. -param1: A list of PyCtxt that represent the encrypted coefficients of the polynome. The first elements of the list must be a PyCtxt that represent a0. The second element must be a PyCtxt that represent a1, etc... |





