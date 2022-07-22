import importlib.resources
from ctypes import cdll

with importlib.resources.path("unblob", "libmath.so") as libmath_so:
    zigmath = cdll.LoadLibrary(str(libmath_so))

calculate_entropy = zigmath.calculate_entropy
