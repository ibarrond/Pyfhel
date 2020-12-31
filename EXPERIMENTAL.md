### Experimental (not supported)
Only for Ubuntu OS, after cloning you can install and compile all libraries as shared (.so) using the Makefiles on this project. To do so, run inside the `Pyfhel` directory:

	   > ./configure		# Just puts all makefiles in their correct directories
	   > make
	   > sudo make install

You can also install just SEAL and Afhel. Just run `make SEAL|Afhel` in the `Pyfhel` directory and `make install` inside `Pyfhel/Afhel` or `Pyfhel/SEAL` directory respectively. Makefiles also have `clean` and `uninstall` commands, as well as `make sourceFileName_x` command to compile and link a source file (.cpp) with them.