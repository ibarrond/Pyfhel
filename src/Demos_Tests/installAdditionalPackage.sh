#!/bin/bash
# since Bash v4

# Upgrade pip
sudo pip install --upgrade pip
#Install the following libraries by pip: numpy scipy matplotlib ipython jupyter pandas sympy nose
sudo python -m pip install --user numpy scipy matplotlib ipython jupyter pandas sympy nose
#Install the following libraries by apt-get: numpy scipy matplotlib ipython jupyter pandas sympy nose
sudo apt-get install python-numpy python-scipy python-matplotlib ipython ipython-notebook python-pandas python-sympy python-nose
#Install the following libraries by apt-get: python-tk
sudo apt-get install python-tk


