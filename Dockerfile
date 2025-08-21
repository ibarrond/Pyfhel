ARG PY_VERSION="3.12"
ARG VENV_PATH="home/venv"
ARG REPO_PATH="home/Pyfhel"

FROM ubuntu:latest
# Prepare system
RUN apt-get update
RUN apt-get install git -y
# Install Python
ARG PY_VERSION
RUN apt-get install python${PY_VERSION} -y
RUN apt-get install python3-pip -y
RUN apt-get install python3-venv -y
# Create virtual environment
ARG VENV_PATH
RUN python${PY_VERSION} -m venv ${VENV_PATH}
# Clone latest version and install repo
ARG REPO_PATH
RUN git clone --recursive https://github.com/ibarrond/Pyfhel ${REPO_PATH}
RUN . ${VENV_PATH}/bin/activate && cd ${REPO_PATH} && pip install . -v