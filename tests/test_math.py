from pathlib import Path
from typing import List

import pytest

from unblob.math import calculate_buffer_size, calculate_entropy, draw_entropy_plot


@pytest.mark.parametrize(
    "file_size, chunk_count, min_limit, max_limit, expected",
    [
        (1000, 1, 10, 100, 100),
        (1000, 10, 10, 100, 100),
        (1000, 100, 10, 100, 10),
    ],
)
def test_calculate_buffer_size(
    file_size: int, chunk_count: int, min_limit: int, max_limit: int, expected: int
):
    assert expected == calculate_buffer_size(
        file_size, chunk_count=chunk_count, min_limit=min_limit, max_limit=max_limit
    )


def test_draw_entropy_plot_error():
    with pytest.raises(TypeError):
        draw_entropy_plot([])


@pytest.mark.parametrize(
    "percentages",
    [
        pytest.param([0.0] * 100, id="zero-array"),
        pytest.param([99.99] * 100, id="99-array"),
        pytest.param([100.0] * 100, id="100-array"),
    ],
)
def test_draw_entropy_plot_no_exception(percentages: List[float]):
    assert draw_entropy_plot(percentages) is None


@pytest.mark.parametrize(
    "path, draw_plot",
    [
        pytest.param(Path("/proc/self/exe"), True, id="draw-plot"),
        pytest.param(Path("/proc/self/exe"), False, id="no-plot"),
    ],
)
def test_calculate_entropy_no_exception(path: Path, draw_plot: bool):
    assert calculate_entropy(path, draw_plot=draw_plot) is None
