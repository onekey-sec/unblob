from typing import Any

from unblob.singleton import SingletonMeta


def test():
    class ClassWithMeta(metaclass=SingletonMeta):
        count: Any = 0

        def __init__(self):
            # tests, that __init__ is called exactly once
            self.count += 1

    a = ClassWithMeta()
    b = ClassWithMeta()
    assert a is b
    assert a.count == b.count == 1

    a.count = "changed"

    class DerivedClassWithMeta(ClassWithMeta):
        pass

    c = DerivedClassWithMeta()
    assert c.count == 1
    d = DerivedClassWithMeta()
    assert c is d
    assert c.count == d.count == 1

    assert a.count == b.count == "changed"

    assert ClassWithMeta.count == 0
    assert DerivedClassWithMeta.count == 0
