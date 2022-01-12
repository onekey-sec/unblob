from pathlib import Path

import pytest

from unblob.handlers import Handler
from unblob.logging import configure_logger


@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    configure_logger(verbose=True, extract_root=Path(""))


class TestHandler(Handler):
    NAME = "test_handler"
    YARA_RULE = r"""
        strings:
            $handler1_magic = { 21 3C }
        condition:
            $handler1_magic
    """

    def calculate_chunk(self, *args, **kwargs):
        pass

    @staticmethod
    def make_extract_command(*args, **kwargs):
        return ["testcommand", "for", "test", "handler"]


def pytest_benchmark_scale_unit(config, unit, benchmarks, best, worst, sort):
    prefix = ""
    scale = 1.0

    for benchmark in benchmarks:
        input_dir = benchmark["params"].get("input_dir")
        if not input_dir or "scaled" in benchmark:
            continue
        input_size = sum(
            f.stat().st_size for f in input_dir.glob("**/*") if f.is_file()
        )
        scale_factor = 1024 * 1024 / input_size
        benchmark["ops"] /= scale_factor
        for time_idx in (
            "hd15iqr",
            "iqr",
            "ld15iqr",
            "max",
            "mean",
            "median",
            "min",
            "q1",
            "q3",
            # "stddev",
            "total",
        ):
            benchmark[time_idx] *= scale_factor
        benchmark["scaled"] = True

    return prefix, scale
