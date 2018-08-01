FROM ubuntu:bionic
RUN apt-get update && apt-get install lzip git make sudo -y
RUN git clone --recursive https://github.com/ibarrond/Pyfhel
RUN cd Pyfhel/src && ./configure && make all
