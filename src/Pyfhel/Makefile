INSTALLER=setup.py
CC=sudo python
CMD=install
COMP_OBJ= *.pyc *.c *.cpp build


all: Pyfhel.pyx PyPtxt.py PyCtxt.py
	$(CC) $(INSTALLER) $(CMD)

clean:
	sudo rm -rf $(COMP_OBJ)
