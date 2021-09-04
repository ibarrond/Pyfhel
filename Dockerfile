FROM ubuntu:bionic
RUN apt-get update && apt-get install lzip git make sudo -y
RUN sudo apt-get install software-properties-common -y
RUN sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
RUN sudo apt-get update
RUN sudo apt-get install gcc-6 g++-6 python3.8 -y
RUN sudo apt-get install -y curl
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN sudo apt install python3.8-distutils -y
RUN python3.8 get-pip.py
RUN echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
RUN . ~/.bashrc
RUN sudo apt-get install build-essential libssl-dev libffi-dev python3.8-dev -y
RUN git clone --recursive https://github.com/ibarrond/Pyfhel
RUN cd Pyfhel && pip3 install .