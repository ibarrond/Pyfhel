Normally, every libraries you will need to run the demos are already installed in your computer.
However, in the case you encountered some issues or if you have installed Pyfhel manually without the easy install, you will need to install additional libraries to run Demo_Pyfhel.py.
To do so, you have two ways to do it:

Method 1 (recommended):
Run the following batch file: installAdditionalPackage.sh, by running the following command in this current folder:

./installAdditionalPackage.sh


Method 2 (not recommended):
Perform the following command:
  >sudo pip install --upgrade pip

  >sudo python -m pip install --user numpy scipy matplotlib ipython jupyter pandas sympy nose

  >sudo apt-get install python-numpy python-scipy python-matplotlib ipython ipython-notebook python-pandas python-sympy python-nose

  >sudo apt-get install python-tk
  
Then, when you have done one of the previous method, you can see how to use the demo by perform the following command:
  >python Demo_Pyfhel.py -h
  
For exemple, you could run the following command to perform the demo:
  >python Demo_Pyfhel.py -f -g
  
