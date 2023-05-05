import multiprocessing
import shutil
from operator import attrgetter
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

import attr
import magic
import plotext as plt
from structlog import get_logger
from unblob_native import math_tools as mt

from unblob.handlers import BUILTIN_HANDLERS, Handlers

from .extractor import carve_unknown_chunk, carve_valid_chunk, fix_extracted_directory
from .file_utils import iterate_file
from .finder import search_chunks
from .iter_utils import pairwise
from .logging import noformat
from .models import (
    Chunk,
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
    EntropyReport,
    ExtractDirectoryExistsReport,
    FileMagicReport,
    HashReport,
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
    "SQLite",
    "compiled Java class",
    "TrueType Font data",
    "PDF document",
    "magic binary file",
    "MS Windows icon resource",
    "PE32",
    "Web Open Font Format",
    "GNU message catalog",
    "Xilinx BIT data",
    "Microsoft Excel",
    "Microsoft Word",
    "Microsoft PowerPoint",
    "Microsoft OOXML",
    "OpenDocument",
    "Macromedia Flash data",
    "MPEG",
    "HP Printer Job Language",
    "Erlang BEAM file",
    "python",  # (e.g. python 2.7 byte-compiled)
    "Composite Document File V2 Document",
    "Windows Embedded CE binary image",
)


@attr.define(kw_only=True)
class ExtractionConfig:
    extract_root: Path = attr.field(converter=lambda value: value.resolve())
    force_extract: bool = False
    entropy_depth: int
    entropy_plot: bool = False
    max_depth: int = DEFAULT_DEPTH
    skip_magic: Iterable[str] = DEFAULT_SKIP_MAGIC
    skip_extraction: bool = False
    process_num: int = DEFAULT_PROCESS_NUM
    keep_extracted_chunks: bool = False
    extract_suffix: str = "_extract"
    handlers: Handlers = BUILTIN_HANDLERS

    def get_extract_dir_for(self, path: Path) -> Path:
        """Return extraction dir under root with the name of path."""
        try:
            relative_path = path.relative_to(self.extract_root)
        except ValueError:
            # path is not inside root, i.e. it is an input file
            relative_path = Path(path.name)
        extract_name = path.name + self.extract_suffix
        extract_dir = self.extract_root / relative_path.with_name(extract_name)
        return extract_dir.expanduser().resolve()


@terminate_gracefully
def process_file(
    config: ExtractionConfig, input_path: Path, report_file: Optional[Path] = None
) -> ProcessResult:
    task = Task(
        chunk_id="",
        path=input_path,
        depth=0,
    )

    if not input_path.is_file():
        raise ValueError("input_path is not a file", input_path)

    extract_dir = config.get_extract_dir_for(input_path)
    if config.force_extract and extract_dir.exists():
        logger.info("Removing extract dir", path=extract_dir)
        shutil.rmtree(extract_dir)

    if not prepare_report_file(config, report_file):
        logger.error(
            "File not processed, as report could not be written", file=input_path
        )
        return ProcessResult()

    process_result = _process_task(config, task)

    # ensure that the root extraction directory is created even for empty extractions
    extract_dir.mkdir(parents=True, exist_ok=True)

    if report_file:
        write_json_report(report_file, process_result)

    return process_result


def _process_task(config: ExtractionConfig, task: Task) -> ProcessResult:
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
        pool.submit(task)
        pool.process_until_done()

    return aggregated_result


def prepare_report_file(config: ExtractionConfig, report_file: Optional[Path]) -> bool:
    """Prevent report writing failing after an expensive extraction.

    Should be called before processing tasks.

    Returns True if there is no foreseen problem,
            False if report writing is known in advance to fail.
    """
    if not report_file:
        # we will not write report at all
        return True

    if report_file.exists():
        if config.force_extract:
            logger.warning("Removing existing report file", path=report_file)
            try:
                report_file.unlink()
            except OSError as e:
                logger.error(
                    "Can not remove existing report file",
                    path=report_file,
                    msg=str(e),
                )
                return False
        else:
            logger.error(
                "Report file exists and --force not specified", path=report_file
            )
            return False

    # check that the report directory can be written to
    try:
        report_file.write_text("")
        report_file.unlink()
    except OSError as e:
        logger.error("Can not create report file", path=report_file, msg=str(e))
        return False

    return True


def write_json_report(report_file: Path, process_result: ProcessResult):
    try:
        report_file.write_text(process_result.to_json())
    except OSError as e:
        logger.error("Can not write JSON report", path=report_file, msg=str(e))
    except Exception:
        logger.exception("Can not write JSON report", path=report_file)
    else:
        logger.info("JSON report written", path=report_file)


class Processor:
    def __init__(self, config: ExtractionConfig):
        self._config = config
        # libmagic helpers
        # file magic uses a rule-set to guess the file type, however as rules are added they could
        # shadow each other. File magic uses rule priorities to determine which is the best matching
        # rule, however this could shadow other valid matches as well, which could eventually break
        # any further processing that depends on magic.
        # By enabling keep_going (which eventually enables MAGIC_CONTINUE) all matching patterns
        # will be included in the magic string at the cost of being a bit slower, but increasing
        # accuracy by no shadowing rules.
        self._get_magic = magic.Magic(keep_going=True).from_file
        self._get_mime_type = magic.Magic(mime=True).from_file

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
        stat_report = StatReport.from_path(task.path)
        result.add_report(stat_report)
        log = logger.bind(path=task.path)

        if task.depth >= self._config.max_depth:
            # TODO: Use the reporting feature to warn the user (ONLY ONCE) at the end of execution, that this limit was reached.
            log.debug("Reached maximum depth, stop further processing")
            return

        if stat_report.is_dir:
            log.debug("Found directory")
            for path in task.path.iterdir():
                result.add_subtask(
                    Task(
                        chunk_id=task.chunk_id,
                        path=path,
                        depth=task.depth,
                    )
                )
            return

        if not stat_report.is_file:
            log.debug(
                "Ignoring special file (link, chrdev, blkdev, fifo, socket, door)."
            )
            return

        magic = self._get_magic(task.path)
        mime_type = self._get_mime_type(task.path)
        logger.debug("Detected file-magic", magic=magic, path=task.path, _verbosity=2)

        magic_report = FileMagicReport(magic=magic, mime_type=mime_type)
        result.add_report(magic_report)

        hash_report = HashReport.from_path(task.path)
        result.add_report(hash_report)

        if stat_report.size == 0:
            log.debug("Ignoring empty file")
            return

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

        self.carve_dir = config.get_extract_dir_for(self.task.path)

    def process(self):
        logger.debug("Processing file", path=self.task.path, size=self.size)

        if self.carve_dir.exists():
            # Extraction directory is not supposed to exist, it is usually a simple mistake of running
            # unblob again without cleaning up or using --force.
            # It would cause problems continuing, as it would mix up original and extracted files,
            # and it would just introduce weird, non-deterministic problems due to interference on paths
            # by multiple workers (parallel processing, modifying content (fix_symlink),
            # and `mmap` + open for write with O_TRUNC).
            logger.error(
                "Skipped: extraction directory exists", extract_dir=self.carve_dir
            )
            self.result.add_report(ExtractDirectoryExistsReport(path=self.carve_dir))
            return

        with File.from_path(self.task.path) as file:
            all_chunks = search_chunks(
                file, self.size, self.config.handlers, self.result
            )
            outer_chunks = remove_inner_chunks(all_chunks)
            unknown_chunks = calculate_unknown_chunks(outer_chunks, self.size)
            assign_file_to_chunks(outer_chunks, file=file)
            assign_file_to_chunks(unknown_chunks, file=file)

            if outer_chunks or unknown_chunks:
                self._process_chunks(file, outer_chunks, unknown_chunks)
            else:
                # we don't consider whole files as unknown chunks, but we still want to
                # calculate entropy for whole files which produced no valid chunks
                entropy = self._calculate_entropy(self.task.path)
                if entropy:
                    self.result.add_report(entropy)

    def _process_chunks(
        self,
        file: File,
        outer_chunks: List[ValidChunk],
        unknown_chunks: List[UnknownChunk],
    ):
        if unknown_chunks:
            logger.warning("Found unknown Chunks", chunks=unknown_chunks)

        for chunk in unknown_chunks:
            carved_unknown_path = carve_unknown_chunk(self.carve_dir, file, chunk)
            entropy = self._calculate_entropy(carved_unknown_path)
            self.result.add_report(chunk.as_report(entropy=entropy))

        for chunk in outer_chunks:
            self._extract_chunk(file, chunk)

    def _calculate_entropy(self, path: Path) -> Optional[EntropyReport]:
        if self.task.depth < self.config.entropy_depth:
            report = calculate_entropy(path)
            if self.config.entropy_plot:
                logger.debug(
                    "Entropy chart",
                    # New line so that chart title will be aligned correctly in the next line
                    chart="\n"
                    + format_entropy_plot(report.percentages, report.block_size),
                    path=path,
                    _verbosity=3,
                )
            return report
        return None

    def _extract_chunk(self, file, chunk: ValidChunk):
        skip_carving = chunk.is_whole_file
        if skip_carving:
            inpath = self.task.path
            extract_dir = self.carve_dir
            carved_path = None
        else:
            inpath = carve_valid_chunk(self.carve_dir, file, chunk)
            extract_dir = self.carve_dir / (inpath.name + self.config.extract_suffix)
            carved_path = inpath

        if extract_dir.exists():
            # Extraction directory is not supposed to exist, it mixes up original and extracted files,
            # and it would just introduce weird, non-deterministic problems due to interference on paths
            # by multiple workers (parallel processing, modifying content (fix_symlink),
            # and `mmap` + open for write with O_TRUNC).
            logger.error(
                "Skipped: extraction directory exists",
                extract_dir=extract_dir,
                chunk=chunk,
            )
            self.result.add_report(
                chunk.as_report([ExtractDirectoryExistsReport(path=extract_dir)])
            )
            return

        if self.config.skip_extraction:
            fix_extracted_directory(extract_dir, self.result)
            return

        extraction_reports = []
        try:
            chunk.extract(inpath, extract_dir)

            if carved_path and not self.config.keep_extracted_chunks:
                logger.debug("Removing extracted chunk", path=carved_path)
                carved_path.unlink()

        except ExtractError as e:
            extraction_reports.extend(e.reports)
        except Exception as exc:
            logger.exception("Unknown error happened while extracting chunk")
            extraction_reports.append(UnknownError(exception=exc))

        self.result.add_report(chunk.as_report(extraction_reports))

        # we want to get consistent partial output even in case of unforeseen problems
        fix_extracted_directory(extract_dir, self.result)
        delete_empty_extract_dir(extract_dir)

        if extract_dir.exists():
            self.result.add_subtask(
                Task(
                    chunk_id=chunk.chunk_id,
                    path=extract_dir,
                    depth=self.task.depth + 1,
                )
            )


def assign_file_to_chunks(chunks: Sequence[Chunk], file: File):
    for chunk in chunks:
        assert chunk.file is None
        chunk.file = file


def delete_empty_extract_dir(extract_dir: Path):
    if extract_dir.exists() and not any(extract_dir.iterdir()):
        extract_dir.rmdir()


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


def calculate_entropy(path: Path) -> EntropyReport:
    """Calculate and log shannon entropy divided by 8 for the file in chunks.

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

    # Smaller chunk size would be very slow to calculate.
    # 1Mb chunk size takes ~ 3sec for a 4,5 GB file.
    block_size = calculate_block_size(
        file_size,
        chunk_count=80,
        min_limit=1024,
        max_limit=1024 * 1024,
    )

    entropy_sum = 0.0
    with File.from_path(path) as file:
        for chunk in iterate_file(file, 0, file_size, buffer_size=block_size):
            entropy = mt.shannon_entropy(chunk)
            entropy_percentage = round(entropy / 8 * 100, 2)
            percentages.append(entropy_percentage)
            entropy_sum += entropy * len(chunk)

    report = EntropyReport(
        percentages=percentages,
        block_size=block_size,
        mean=entropy_sum / file_size / 8 * 100,
    )

    logger.debug(
        "Entropy calculated",
        path=path,
        size=file_size,
        block_size=report.block_size,
        mean=round(report.mean, 2),
        highest=round(report.highest, 2),
        lowest=round(report.lowest, 2),
    )

    return report


def calculate_block_size(
    file_size, *, chunk_count: int, min_limit: int, max_limit: int
) -> int:
    """Split the file into even sized chunks, limited by lower and upper values."""
    # We don't care about floating point precision here
    block_size = file_size // chunk_count
    block_size = max(min_limit, block_size)
    block_size = min(block_size, max_limit)
    return block_size


def format_entropy_plot(percentages: List[float], block_size: int):
    # start from scratch
    plt.clear_figure()
    # go colorless
    plt.clear_color()
    plt.title("Entropy distribution")
    # plt.xlabel(humanize.naturalsize(block_size))
    plt.xlabel(f"{block_size} bytes")
    plt.ylabel("entropy %")

    plt.scatter(percentages, marker="dot")
    # 16 height leaves no gaps between the lines
    plt.plot_size(100, 16)
    plt.ylim(0, 100)
    # Draw ticks every 1Mb on the x axis.
    plt.xticks(range(len(percentages) + 1))
    # Always show 0% and 100%
    plt.yticks(range(0, 101, 10))

    return plt.build()
