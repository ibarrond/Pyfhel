#   --------------------------------------------------------------------
#   Pyfhel.pyx
#   Author: Alberto Ibarrondo
#   Date: 17/07/2018
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
"""PYFHEL, PYthon For Homomorphic Encryption Libraries.

Encrypted addition, multiplication, substraction, exponentiation of 
integers/doubles. Implementation of homomorphic encryption using 
SEAL/PALISADE/HELIB as backend. Pyfhel works with PyPtxt as plaintext 
class and PyCtxt as cyphertext class.

Example:
    >>> he = Pyfhel()
    >>> he.ContextGen(p=65537)
    >>> he.KeyGen(p=65537)
    >>> p1 = he.encode(4)
    >>> p2 = he.encode(2)
    >>> c1 = he.encrypt(p1)
    >>> c2 = he.encrypt(p2)
    >>> c1 = c1 + c2
    >>> p_res = he.decrypt(c1)
    6
"""    
