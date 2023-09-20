import pytest

from unblob.iter_utils import get_intervals


@pytest.mark.parametrize(
    "values, expected",
    [
        ([], set()),
        ([0, 0], {0}),
        ([0, 0, 0], {0}),
        ([1, 2, 3], {1}),
        ([1, 5, 8, 8, 10, 15], {4, 3, 0, 2, 5}),
    ],
)
def test_get_internals(values, expected):
    assert get_intervals(values) == expected
