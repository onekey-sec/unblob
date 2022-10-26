# from typing import Dict, Type, TypeVar

# X = TypeVar("X")
# _instances: Dict[Type[X], X] = {}

_instances = {}


class SingletonMeta(type):
    """Metaclass, calls __init__ once."""

    def __call__(cls, *args, **kwargs):
        global _instances
        try:
            return _instances[cls]
        except KeyError:
            _instances[cls] = super().__call__(*args, **kwargs)
            # _instances[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)
        return _instances[cls]
