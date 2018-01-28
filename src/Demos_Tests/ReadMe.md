To run Demo_Pyfhel.py, you have to install additional packages.
To do so, you have to way to do it:

Method 1 (recommended):
Run the following batch file: installAdditionalPackage.sh, by running the following command:
./installAdditionalPackage.sh


Method 1 (not recommended):
Perform fist the following command:
  >sudo pip install --upgrade pip
  >sudo python -m pip install --user numpy scipy matplotlib ipython jupyter pandas sympy nose
  >sudo apt-get install python-numpy python-scipy python-matplotlib ipython ipython-notebook python-pandas python-sympy python-nose
  >sudo apt-get install python-tk
  
Then, you can see how to use the demo by perform the following command:
  >python Demo_Pyfhel.py -h
  
For exemple, you could run the following command to perform the demo:
  >python Demo_Pyfhel.py -f -g
  
