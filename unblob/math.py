try:
    from ._rust import shannon_entropy
except ImportError:
    from ._py.math import shannon_entropy  # noqa: F401
