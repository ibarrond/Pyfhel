CC = g++
CFLAGS = -g -O2 -std=c++11 -Wfatal-errors -Wshadow -Wall  -pthread -DFHE_THREADS -DFHE_DCRT_THREADS -DFHE_BOOT_THREADS -I/usr/local/include


LDLIBS = -lntl -lgmp -lm -lfhe -lafhel

./%_x: %.cpp
		$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
		-rm -f *.aenv *_x

info:
		: Afhel requires HElib, GMP and NTL 10.0.0 or higher
		: Compilation flags are 'CFLAGS=$(CFLAGS)'
		: If errors occur, try adding/removing '-std=c++11' in Makefile
