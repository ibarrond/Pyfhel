Contributing
==================

This is the process to develop/contribute to Pyfhel:

This is the standard process to develop/contribute:
1. *Code a new feature/fix a bug*. Using [Cython](https://cython.readthedocs.io/en/latest/) for the ``.pyx`` and ``.pxd`` extensions, C++ for ``Afhel`` or Python for examples/tests/other.

2. *Build/Install Pyfhel locally*. Use ``pip install -v -v .`` for a verbose installation.

3. *Test changes (requires installing `pytest`)*. Run the tests locally by executing ``pytest .``  in the root directory, and make sure all tests pass. 
	
   - *Code coverage (requires installing ``pytest-cov``)*. Add an empty ``.cov`` file in the root directory, and build/install the project locally (``pip install .``). To run coverage tests, execute ``pytest --cov .`` in the root directory, and then ``coverage html`` to obtain a report.

You're ready to go! Just create a pull request to the original repo.
