# Pyfhel Documentation

This folder contains the up-to-date documentation of Pyfhel.

The documentation is built with `sphinx` and `sphinx-gallery` (you can install them using `pip install -r docs/requirements.txt` for Python3). To generate it, just run `make html` (Linux) or `.\make.bat html` (Windows). The resulting **`html\index.html`** file serves as homepage for the entire static documentation.

To contribute to the documentation, your best shot is to create a new `Demo_*.py` file showcasing your particular usecase, and add extensive comments following the same comment format from the other demos (just use one of them as a template). `sphinx` will execute it and add all your comments to the existing documentation.
