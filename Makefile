CC = g++
CFLAGS = -g -O2 -std=c++11 -Wfatal-errors -Wshadow -Wall  -pthread -DFHE_THREADS -DFHE_DCRT_THREADS -DFHE_BOOT_THREADS -I/usr/local/include


LDLIBS = -L/usr/local/lib -lntl -lgmp -lm 
AR = ar
ARFLAGS = ruv

HELIB_SRC=./HElib/src
HELIB_ARCH = $(HELIB_SRC)/fhe.a
AFHEL_DIR=./Afhel
HEADER = $(AFHEL_DIR)/Afhel.h
SRC = $(AFHEL_DIR)/Afhel.cpp
OBJ = $(AFHEL_DIR)/Afhel.o
AFHEL_ARCH = $(AFHEL_DIR)/Afhel.a

UTILS = ./utils/Timer.cpp

HELIB_OBJ = $(HELIB_SRC)/NumbTh.o $(HELIB_SRC)/timing.o $(HELIB_SRC)/bluestein.o $(HELIB_SRC)/PAlgebra.o  $(HELIB_SRC)/CModulus.o $(HELIB_SRC)/FHEContext.o $(HELIB_SRC)/IndexSet.o $(HELIB_SRC)/DoubleCRT.o $(HELIB_SRC)/FHE.o $(HELIB_SRC)/KeySwitching.o $(HELIB_SRC)/Ctxt.o $(HELIB_SRC)/EncryptedArray.o $(HELIB_SRC)/replicate.o $(HELIB_SRC)/hypercube.o $(HELIB_SRC)/matching.o $(HELIB_SRC)/powerful.o $(HELIB_SRC)/BenesNetwork.o $(HELIB_SRC)/permutations.o $(HELIB_SRC)/PermNetwork.o $(HELIB_SRC)/OptimizePermutations.o $(HELIB_SRC)/eqtesting.o $(HELIB_SRC)/polyEval.o $(HELIB_SRC)/extractDigits.o $(HELIB_SRC)/EvalMap.o $(HELIB_SRC)/recryption.o $(HELIB_SRC)/debugging.o $(HELIB_SRC)/matmul.o $(HELIB_SRC)/matmul1D.o $(HELIB_SRC)/blockMatmul.o $(HELIB_SRC)/blockMatmul1D.o


all: Afhel.a

obj: $(OBJ)

%.o: %.cpp $(HEADER)
	$(CC) $(CFLAGS) -I$(HELIB_SRC) -c $< $(LDLIBS)

Afhel.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $(OBJ) $(HELIB_ARCH) $(HELIB_OBJ)

./%_x: %.cpp Afhel.a
	$(CC) $(CFLAGS) -I$(HELIB_SRC) -o $@ $< $(AFHEL_ARCH) $(HELIB_ARCH) $(LDLIBS) $(UTILS)


clean:
	-rm -f *.o *_x *_x.exe *.a core.* $(HELIB_SRC)/*.a $(HELIB_SRC)/*.o $(AFHEL_DIR)/*.a $(AFHEL_DIR)/*.o
	-rm -rf *.dSYM

info:
	: Afhel requires HElib and NTL 10.0.0 or higher
	: Compilation flags are 'CFLAGS=$(CFLAGS)'
	: If errors occur, try adding/removing '-std=c++11' in Makefile
	:
