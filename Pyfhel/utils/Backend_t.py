from enum import Enum
class Backend_t(Enum):
    """An Enum to define the backend"""

    none=0x0
    """Default value of 0 for non defined backend."""

    seal=0x1
    """Microsof's SEAL library. https://github.com/microsoft/SEAL/"""

    palisade=0x2
    """PALISADE library. https://gitlab.com/palisade/"""