from unittest.mock import Mock

from unblob.logging import LazyField


def test_lazy_field():
    expected_value = "expensive calculation"
    lf = LazyField(lambda: expected_value)
    assert repr(lf) == expected_value


def test_lazy_field_function_only_called_once():
    mock_func = Mock(return_value="string")
    lf = LazyField(mock_func)
    repr(lf)
    repr(lf)
    mock_func.assert_called_once()
