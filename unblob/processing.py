import multiprocessing
import shutil
import statistics
from operator import attrgetter
from pathlib import Path
from typing import Iterable, List

import attr
import plotext as plt
from structlog import get_logger

from unblob.handlers import BUILTIN_HANDLERS, Handlers

from .extractor import carve_unknown_chunks, carve_valid_chunk, fix_extracted_directory
from .file_utils import iterate_file, valid_path
from .finder import search_chunks
from .iter_utils import pairwise
from .logging import noformat
from .math import shannon_entropy
from .models import (
    ExtractError,
    File,
    ProcessResult,
    Task,
    TaskResult,
    UnknownChunk,
    ValidChunk,
)
from .pool import make_pool
from .report import (
    ExtractDirectoryExistsReport,
    FileMagicReport,
    StatReport,
    UnknownError,
)
from .signals import terminate_gracefully

logger = get_logger()

DEFAULT_DEPTH = 10
DEFAULT_PROCESS_NUM = multiprocessing.cpu_count()
DEFAULT_SKIP_MAGIC = (
    "BFLT",
    "JPEG",
    "GIF",
    "PNG",
    "compiled Java class",
    "TrueType Font data",
    "PDF document",
    "magic binary file",
    "MS Windows icon resource",
)


@attr.define(kw_only=True)
class ExtractionConfig:
    extract_root: Path
    force_extract: bool = False
    entropy_depth: int
    entropy_plot: bool = False
    max_depth: int = DEFAULT_DEPTH
    skip_magic: Iterable[str] = DEFAULT_SKIP_MAGIC
    process_num: int = DEFAULT_PROCESS_NUM
    keep_extracted_chunks: bool = False
    extract_suffix: str = "_extract"
    handlers: Handlers = BUILTIN_HANDLERS


@terminate_gracefully
def process_file(config: ExtractionConfig, path: Path) -> ProcessResult:
    task = Task(
        path=path,
        depth=0,
    )

    errors = check_extract_directory(task, config)
    if errors:
        return ProcessResult(errors)

    result = _process_one_file(config, task)

    return result


def check_extract_directory(task: Task, config: ExtractionConfig):
    errors = []

    extract_dir = get_extract_dir_for_input(config, task.path)
    if extract_dir.exists():
        if config.force_extract:
            shutil.rmtree(extract_dir)
        else:
            report = ExtractDirectoryExistsReport(path=extract_dir)
            logger.error("Extraction directory already exist", **report.asdict())
            errors.append(TaskResult(task, [report]))

    return errors


def _process_one_file(config: ExtractionConfig, root_task: Task) -> ProcessResult:
    processor = Processor(config)
    aggregated_result = ProcessResult()

    def process_result(pool, result):
        for new_task in result.subtasks:
            pool.submit(new_task)
        aggregated_result.register(result)

    pool = make_pool(
        process_num=config.process_num,
        handler=processor.process_task,
        result_callback=process_result,
    )

    with pool:
        pool.submit(root_task)
        pool.process_until_done()

    return aggregated_result


class Processor:
    def __init__(self, config: ExtractionConfig):
        self._config = config

    def process_task(self, task: Task) -> TaskResult:
        result = TaskResult(task)
        try:
            self._process_task(result, task)
        except Exception as exc:
            self._process_error(result, exc)
        return result

    def _process_error(self, result: TaskResult, exc: Exception):
        error_report = UnknownError(exception=exc)
        result.add_report(error_report)
        logger.exception("Unknown error happened", exc_info=exc)

    def _process_task(self, result: TaskResult, task: Task):
        log = logger.bind(path=task.path)

        if task.depth >= self._config.max_depth:
            # TODO: Use the reporting feature to warn the user (ONLY ONCE) at the end of execution, that this limit was reached.
            log.debug("Reached maximum depth, stop further processing")
            return

        if not valid_path(task.path):
            log.warn("Path contains invalid characters, it won't be processed")
            return

        stat_report = StatReport.from_path(task.path)
        result.add_report(stat_report)

        if stat_report.is_dir:
            log.debug("Found directory")
            for path in task.path.iterdir():
                result.add_subtask(
                    Task(
                        path=path,
                        depth=task.depth,
                    )
                )
            return

        if stat_report.is_link:
            log.debug("Ignoring symlink")
            return

        if stat_report.size == 0:
            log.debug("Ignoring empty file")
            return

        magic_report = FileMagicReport.from_path(task.path)
        result.add_report(magic_report)

        magic = magic_report.magic

        logger.debug("Detected file-magic", magic=magic, path=task.path, _verbosity=2)

        should_skip_file = any(
            magic.startswith(pattern) for pattern in self._config.skip_magic
        )

        if should_skip_file:
            log.debug("Ignoring file based on magic", magic=magic)
            return

        _FileTask(self._config, task, stat_report.size, result).process()


class _FileTask:
    def __init__(
        self,
        config: ExtractionConfig,
        task: Task,
        size: int,
        result: TaskResult,
    ):
        self.config = config
        self.task = task
        self.size = size
        self.result = result

        self.carve_dir = get_extract_dir_for_input(config, self.task.path)

    def process(self):
        logger.debug("Processing file", path=self.task.path, size=self.size)

        with File.from_path(self.task.path) as file:
            all_chunks = search_chunks(
                file, self.size, self.config.handlers, self.result
            )
            outer_chunks = remove_inner_chunks(all_chunks)
            unknown_chunks = calculate_unknown_chunks(outer_chunks, self.size)

            if outer_chunks or unknown_chunks:
                self._process_chunks(file, outer_chunks, unknown_chunks)
            else:
                # we don't consider whole files as unknown chunks, but we still want to
                # calculate entropy for whole files which produced no valid chunks
                self._calculate_entropies([self.task.path])

        self._ensure_root_extract_dir()

    def _process_chunks(
        self,
        file: File,
        outer_chunks: List[ValidChunk],
        unknown_chunks: List[UnknownChunk],
    ):
        carved_unknown_paths = carve_unknown_chunks(
            self.carve_dir, file, unknown_chunks
        )
        self._calculate_entropies(carved_unknown_paths)

        for chunk in outer_chunks:
            self._extract_chunk(file, chunk)

    def _ensure_root_extract_dir(self):
        # ensure that the root extraction directory is created even for empty extractions
        if self.task.depth == 0:
            self.carve_dir.mkdir(parents=True, exist_ok=True)

    def _calculate_entropies(self, paths: List[Path]):
        if self.task.depth < self.config.entropy_depth:
            for path in paths:
                calculate_entropy(path, draw_plot=self.config.entropy_plot)

    def _extract_chunk(self, file, chunk: ValidChunk):
        is_whole_file_chunk = chunk.start_offset == 0 and chunk.end_offset == self.size

        skip_carving = is_whole_file_chunk
        if skip_carving:
            inpath = self.task.path
            extract_dir = self.carve_dir
            carved_path = None
        else:
            inpath = carve_valid_chunk(self.carve_dir, file, chunk)
            extract_dir = self.carve_dir / (inpath.name + self.config.extract_suffix)
            carved_path = inpath

        try:
            chunk.extract(inpath, extract_dir)

            if carved_path and not self.config.keep_extracted_chunks:
                logger.debug("Removing extracted chunk", path=carved_path)
                carved_path.unlink()

        except ExtractError as e:
            for report in e.reports:
                self.result.add_report(report)

        except Exception as exc:
            logger.exception("Unknown error happened while extracting chunk")
            self.result.add_report(UnknownError(exception=exc))

        # we want to get consistent partial output even in case of unforeseen problems
        fix_extracted_directory(extract_dir, self.result)

        if extract_dir.exists():
            self.result.add_subtask(
                Task(
                    path=extract_dir,
                    depth=self.task.depth + 1,
                )
            )


def get_extract_dir_for_input(config: ExtractionConfig, path: Path) -> Path:
    """Extraction dir under root with the name of path."""
    try:
        relative_path = path.relative_to(config.extract_root)
    except ValueError:
        # path is not inside root, i.e. it is an input file
        relative_path = Path(path.name)
    extract_name = path.name + config.extract_suffix
    extract_dir = config.extract_root / relative_path.with_name(extract_name)
    return extract_dir.expanduser().resolve()


def remove_inner_chunks(chunks: List[ValidChunk]) -> List[ValidChunk]:
    """Remove all chunks from the list which are within another bigger chunks."""
    if not chunks:
        return []

    chunks_by_size = sorted(chunks, key=attrgetter("size"), reverse=True)
    outer_chunks = [chunks_by_size[0]]
    for chunk in chunks_by_size[1:]:
        if not any(outer.contains(chunk) for outer in outer_chunks):
            outer_chunks.append(chunk)

    outer_count = len(outer_chunks)
    removed_count = len(chunks) - outer_count
    logger.debug(
        "Removed inner chunks",
        outer_chunk_count=noformat(outer_count),
        removed_inner_chunk_count=noformat(removed_count),
        _verbosity=2,
    )
    return outer_chunks


def calculate_unknown_chunks(
    chunks: List[ValidChunk], file_size: int
) -> List[UnknownChunk]:
    """Calculate the empty gaps between chunks."""
    if not chunks or file_size == 0:
        return []

    sorted_by_offset = sorted(chunks, key=attrgetter("start_offset"))

    unknown_chunks = []

    first = sorted_by_offset[0]
    if first.start_offset != 0:
        unknown_chunk = UnknownChunk(0, first.start_offset)
        unknown_chunks.append(unknown_chunk)

    for chunk, next_chunk in pairwise(sorted_by_offset):
        diff = next_chunk.start_offset - chunk.end_offset
        if diff != 0:
            unknown_chunk = UnknownChunk(
                start_offset=chunk.end_offset,
                end_offset=next_chunk.start_offset,
            )
            unknown_chunks.append(unknown_chunk)

    last = sorted_by_offset[-1]
    if last.end_offset < file_size:
        unknown_chunk = UnknownChunk(
            start_offset=last.end_offset,
            end_offset=file_size,
        )
        unknown_chunks.append(unknown_chunk)

    return unknown_chunks


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
