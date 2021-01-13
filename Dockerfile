FROM ubuntu:focal
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" \
    apt-get -y install tzdata \
    apt-utils \
    git \
    make \
    sudo
RUN sudo apt-get install software-properties-common -y
RUN sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
RUN sudo apt-get update
RUN sudo apt-get install -y build-essential \
    libssl-dev \
    libpython3-all-dev \
    gcc \
    g++ \
    python3 \
    python3-pip \
    zlib1g-dev
RUN pip3 install Cython
COPY . Pyfhel
# RUN git clone --recursive https://github.com/AlbertoPimpo/Pyfhel.git
WORKDIR "./Pyfhel"
RUN git submodule update --init --recursive
RUN pip3 install .
