import statistics
from pathlib import Path
from typing import Callable, List

import plotext as plt

from .file_utils import File, iterate_file

try:
    shannon_entropy: Callable[[bytes], float]
    from ._rust import shannon_entropy  # pyright: ignore[reportMissingImports]
except ImportError:
    from ._py.math import shannon_entropy  # noqa: F401

from structlog import get_logger

logger = get_logger()


def calculate_entropy(path: Path, *, draw_plot: bool):
    """Calculate and log shannon entropy divided by 8 for the file in 1mB chunks.

    Shannon entropy returns the amount of information (in bits) of some numeric
    sequence. We calculate the average entropy of byte chunks, which in theory
    can contain 0-8 bits of entropy. We normalize it for visualization to a
    0-100% scale, to make it easier to interpret the graph.
    """
    percentages = []

    # We could use the chunk size instead of another syscall,
    # but we rely on the actual file size written to the disk
    file_size = path.stat().st_size
    logger.debug("Calculating entropy for file", path=path, size=file_size)

    # Smaller chuk size would be very slow to calculate.
    # 1Mb chunk size takes ~ 3sec for a 4,5 GB file.
    buffer_size = calculate_buffer_size(
        file_size, chunk_count=80, min_limit=1024, max_limit=1024 * 1024
    )

    with File.from_path(path) as file:
        for chunk in iterate_file(file, 0, file_size, buffer_size=buffer_size):
            entropy = shannon_entropy(chunk)
            entropy_percentage = round(entropy / 8 * 100, 2)
            percentages.append(entropy_percentage)

    logger.debug(
        "Entropy calculated",
        mean=round(statistics.mean(percentages), 2),
        highest=max(percentages),
        lowest=min(percentages),
    )

    if draw_plot:
        draw_entropy_plot(percentages)


def calculate_buffer_size(
    file_size, *, chunk_count: int, min_limit: int, max_limit: int
) -> int:
    """Split the file into even sized chunks, limited by lower and upper values."""
    # We don't care about floating point precision here
    buffer_size = file_size // chunk_count
    buffer_size = max(min_limit, buffer_size)
    buffer_size = min(buffer_size, max_limit)
    return buffer_size


def draw_entropy_plot(percentages: List[float]):
    plt.clear_data()
    plt.colorless()
    plt.title("Entropy distribution")
    plt.xlabel("mB")
    plt.ylabel("entropy %")

    plt.scatter(percentages, marker="dot")
    # 16 height leaves no gaps between the lines
    plt.plot_size(100, 16)
    plt.ylim(0, 100)
    # Draw ticks every 1Mb on the x axis.
    plt.xticks(range(len(percentages) + 1))
    # Always show 0% and 100%
    plt.yticks(range(0, 101, 10))

    # New line so that chart title will be aligned correctly in the next line
    logger.debug("Entropy chart", chart="\n" + plt.build(), _verbosity=3)
