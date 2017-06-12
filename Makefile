HELIB_SRC=./HElib/src
CC = g++
CFLAGS = -g -O2 -std=c++11 -Wfatal-errors -Wshadow -Wall  -pthread -DFHE_THREADS -DFHE_DCRT_THREADS -DFHE_BOOT_THREADS -I/usr/local/include


LDLIBS = -L/usr/local/lib -lntl -lgmp -lm 
HELIB_ARCH = $(HELIB_SRC)/fhe.a
AR = ar
ARFLAGS = ruv

HEADER =Afhel.h
SRC = Afhel.cpp
OBJ = Afhel.o

HELIB_OBJ = $(HELIB_SRC)/NumbTh.o $(HELIB_SRC)/timing.o $(HELIB_SRC)/bluestein.o $(HELIB_SRC)/PAlgebra.o  $(HELIB_SRC)/CModulus.o $(HELIB_SRC)/FHEContext.o $(HELIB_SRC)/IndexSet.o $(HELIB_SRC)/DoubleCRT.o $(HELIB_SRC)/FHE.o $(HELIB_SRC)/KeySwitching.o $(HELIB_SRC)/Ctxt.o $(HELIB_SRC)/EncryptedArray.o $(HELIB_SRC)/replicate.o $(HELIB_SRC)/hypercube.o $(HELIB_SRC)/matching.o $(HELIB_SRC)/powerful.o $(HELIB_SRC)/BenesNetwork.o $(HELIB_SRC)/permutations.o $(HELIB_SRC)/PermNetwork.o $(HELIB_SRC)/OptimizePermutations.o $(HELIB_SRC)/eqtesting.o $(HELIB_SRC)/polyEval.o $(HELIB_SRC)/extractDigits.o $(HELIB_SRC)/EvalMap.o $(HELIB_SRC)/recryption.o $(HELIB_SRC)/debugging.o $(HELIB_SRC)/matmul.o $(HELIB_SRC)/matmul1D.o $(HELIB_SRC)/blockMatmul.o $(HELIB_SRC)/blockMatmul1D.o $(HELIB_SRC)/FFT.o


all: Afhel.a

obj: $(OBJ)

%.o: %.cpp $(HEADER)
	$(CC) $(CFLAGS) -I$(HELIB_SRC) -c $< $(LDLIBS)

Afhel.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ) $(HELIB_ARCH) $(HELIB_OBJ)

./%_x: %.cpp Afhel.a
	$(CC) $(CFLAGS) -I$(HELIB_SRC) -o $@ $< Afhel.a $(HELIB_ARCH) $(LDLIBS)


clean:
	-rm -f *.o *_x *_x.exe *.a core.*
	-rm -rf *.dSYM

info:
	: Afhel requires HElib and NTL 10.0.0 or higher
	: Compilation flags are 'CFLAGS=$(CFLAGS)'
	: If errors occur, try adding/removing '-std=c++11' in Makefile
	:
