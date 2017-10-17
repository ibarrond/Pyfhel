CC = g++
CFLAGS = -g -O2 -std=c++11 -Wfatal-errors -Wshadow -Wall  -pthread -DFHE_THREADS -DFHE_DCRT_THREADS -DFHE_BOOT_THREADS -I/usr/local/include

LDLIBS = -lntl -lgmp -lm -lfhe -lafhel


all: Helib Afhel Pyfhel

Helib:
	$(MAKE) -C HElib/src/
	$(MAKE) install -C HElib/src/	

Afhel:
	$(MAKE) -C Afhel/
	$(MAKE) install -C Afhel/

Pyfhel:
	$(MAKE) -C Pyfhel

clean:
	$(MAKE) clean -C HElib/src/
	$(MAKE) clean -C Afhel/
	$(MAKE) clean -C Pyfhel/

uninstall:
	$(MAKE) uninstall -C HElib/src/
	$(MAKE) uninstall -C Afhel/
	$(MAKE) uninstall -C Pyfhel/


./%_x: %.cpp
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

cleanexe:
	-rm -f *.aenv *_x

