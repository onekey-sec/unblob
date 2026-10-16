import itertools


def get_intervals(values: list[int]) -> list[int]:
    """Get all the intervals between numbers.

    It's similar to numpy.diff function.

    Example:
    -------
    >>> get_intervals([1, 4, 5, 6, 10])
    [3, 1, 1, 4]

    """
    all_diffs = []
    for value, next_value in itertools.pairwise(values):
        all_diffs.append(next_value - value)
    return all_diffs
