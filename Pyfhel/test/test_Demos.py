
import sys, contextlib
from io import StringIO
from pathlib import Path

# Redirect stdout of Demos to a string, recover if error.
# https://stackoverflow.com/a/41614610/9670056
@contextlib.contextmanager
def stdoutIO(stdout=None):
    old = sys.stdout
    if stdout is None:
        stdout = StringIO()
    sys.stdout = stdout
    yield stdout
    sys.stdout = old

# Demo execution from https://stackoverflow.com/a/41658338/9670056
def execfile(filepath, globals=None, locals=None):
    filepath = str(filepath)
    if globals is None:
        globals = {}
    globals.update({
        "__file__": filepath,
        "__name__": "__main__",
    })
    with open(filepath, 'rb') as file:
        with stdoutIO() as s:
            exec(compile(file.read(), filepath, 'exec'), globals, locals)
# Examples folder
EXAMPLES_FOLDER = Path(__file__).parents[2].absolute() / 'examples'



################################################################################
#                             COVERAGE TESTS                                   #
################################################################################
def test_Demo_1_Helloworld():
    execfile(EXAMPLES_FOLDER / 'Demo_1_HelloWorld.py')

def test_Demo_2_Integer_BFV():
    execfile(EXAMPLES_FOLDER / 'Demo_2_Integer_BFV.py')

def test_Demo_3_Float_CKKS():
    execfile(EXAMPLES_FOLDER / 'Demo_3_Float_CKKS.py')

def test_Demo_4_SaveNRestore():
    execfile(EXAMPLES_FOLDER / 'Demo_4_SaveNRestore.py')

def test_Demo_5_CS_Client():
    execfile(EXAMPLES_FOLDER / 'Demo_5_CS_Client.py')

def test_Demo_6_MultDepth():
    execfile(EXAMPLES_FOLDER / 'Demo_6_MultDepth.py')

def test_Demo_7_ScalarProd():
    execfile(EXAMPLES_FOLDER / 'Demo_7_ScalarProd.py')

def test_Demo_WAHC21():
    execfile(EXAMPLES_FOLDER / 'Demo_WAHC21.py')