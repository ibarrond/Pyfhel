# Pyfhel Tests
These tests require `pytest` to run. Once installed (e.g. `pip install pytest`), run the tests by executing `pytest`:
```
python -m pytest .
```

To run tests with code coverage, create an empty `.cov` file in the top level directory, then build and install the package, then run the tests with ``
```
python -m pytest --cov .
```
To obtain a report, just run `coverage html` and open the file `htmlcov/index.html` in your browser.

