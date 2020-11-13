Contributing
==================

This is the process to develop/contribute to Pyfhel:

1. *Code a new feature/fix a bug*. Since this project is built using Cython, please refer to `cython documentation <https://cython.readthedocs.io/en/latest/>`_ if you want to help develop it.
2. *Recompile the cython extensions*. After modifying any of the `.pyx`|`pxd` cython files (or the *Afhel* `.cpp` files) you must recompile the cython files. To do so, run the following command:

.. code-block:: bash

    # This will turn `Pyfhel/*.pyx` into the corresponding `Pyfhel/*.cpp` file.
    #  Do not edit the `Pyfhel/*.cpp` files directly!
    > python3 setup.py --CYTHONIZE --fullname
        Compiling Pyfhel/Pyfhel.pyx because it changed.
        Compiling Pyfhel/PyPtxt.pyx because it depends on ./Pyfhel/iostream.pxd.
        [1/2] Cythonizing Pyfhel/Pyfhel.pyx
        [2/2] Cythonizing Pyfhel/PyPtxt.pyx
        Pyfhel-2.0.2

3. *Reinstall Pyfhel locally*. Use either `pip install .` or `python3 setup.py build` (for verbose output and fine control. Run `python3 setup.py --help` for further options).

4. *Test changes locally*. Run the `test.py` file in your environment and make sure all tests are OK:

.. code-block:: bash

    python3 Pyfhel/test.py
        test_PyCtxt_creation_deletion (__main__.PyfhelTestCase) ... (0.0s) ...ok
        test_PyPtxt_PyCtxt (__main__.PyfhelTestCase) ... (0.0s) ...ok
        [...]
        test_Pyfhel_5d_save_restore_int (__main__.PyfhelTestCase) ... (1.239s) ...ok

        ----------------------------------------------------------------------
        Ran 29 tests in 11.907s

        OK
 
5. *Test changes locally*. Run the `test.py` file in your environment and make sure all tests are OK:

6. *Update the version*. To update it, just change the version number on top of this README: Pyfhel [**vA.B.C**]. Bugfixes and minor corrections should increase **C**. New features should increase **B**. Backwards incompatible changes should increase **A**. 

7. *Optional: Add a demo showcasing the new functionality*. The demo will be automatically run as part of the tests and included in the documentation. Check other demos for inspiration on the format.

8. *Optional: Update the docs*. (automatic generation with sphinx in readthedocs).

You're ready to go! Just create a pull request to the `original repo <https://github.com/ibarrond/Pyfhel>`_.