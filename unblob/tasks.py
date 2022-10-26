import itertools
import json
import multiprocessing
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, List, Optional

import attr
import magic
from structlog import get_logger

from .chunks import calculate_unknown_chunks, remove_inner_chunks
from .extractor import carve_chunk
from .file_utils import File
from .finder import search_chunks
from .fixers import fix_extracted_directory
from .handlers import BUILTIN_HANDLERS, Handlers
from .math import calculate_entropy
from .models import Chunk, ExtractError, Handler, ValidChunk
from .report import (
    ChunkReport,
    DeletedInputReport,
    ErrorReport,
    FileMagicReport,
    HashReport,
    Report,
    StatReport,
    UnknownError,
)

logger = get_logger()

# The state transitions are:
#
# file ──► pattern match ──► ValidChunk
#


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
    "PE32+ executable (EFI application)",
    "Web Open Font Format",
    "GNU message catalog",
    "Xilinx BIT data",
    "Microsoft Excel",
    "Microsoft Word",
    "Microsoft PowerPoint",
    "OpenDocument",
)


@attr.define(kw_only=True)
class ExtractionConfig:
    extract_root: Path = attr.field(converter=lambda value: value.resolve())
    force_extract: bool = False
    entropy_depth: int
    entropy_plot: bool = False
    max_depth: int = DEFAULT_DEPTH
    skip_magic: Iterable[str] = DEFAULT_SKIP_MAGIC
    process_num: int = DEFAULT_PROCESS_NUM
    keep_extracted_chunks: bool = False
    extract_suffix: str = "_extract"
    handlers: Handlers = BUILTIN_HANDLERS

    # libmagic helpers
    # file magic uses a rule-set to guess the file type, however as rules are added they could
    # shadow each other. File magic uses rule priorities to determine which is the best matching
    # rule, however this could shadow other valid matches as well, which could eventually break
    # any further processing that depends on magic.
    # By enabling keep_going (which eventually enables MAGIC_CONTINUE) all matching patterns
    # will be included in the magic string at the cost of being a bit slower, but increasing
    # accuracy by no shadowing rules.
    get_magic: Callable[[Path], str] = attr.field(
        factory=lambda: magic.Magic(keep_going=True).from_file
    )
    get_mime_type: Callable[[Path], str] = attr.field(
        factory=lambda: magic.Magic(mime=True).from_file
    )

    def get_extract_dir_for(self, path: Path) -> Path:
        """Extraction dir under root with the name of path."""
        try:
            relative_path = path.relative_to(self.extract_root)
        except ValueError:
            # path is not inside root, i.e. it is an input file
            relative_path = Path(path.name)
        extract_name = path.name + self.extract_suffix
        extract_dir = self.extract_root / relative_path.with_name(extract_name)
        return extract_dir.expanduser().resolve()


@attr.define(frozen=True)
class Task:
    """A generic task working on a resource backed vaguely by the file system"""

    path: Path
    depth: int
    chunk_id: str
    # FIXME: chunk_id should be (parent task id?) removed.

    @property
    def logger(self):
        logger_with_path = logger.bind(path=self.path)
        return logger_with_path

    def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
        # we do not know yet what do we have...
        return result


@attr.define(frozen=True)
class ClassifierTask(Task):
    """Determine how to handle a file path."""

    def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
        stat_report = StatReport.from_path(self.path)
        result.add_report(stat_report)

        if stat_report.is_dir:
            self.logger.debug("Found directory")
            task = DirTask(
                chunk_id=self.chunk_id,
                path=self.path,
                depth=self.depth,
            )
            result.add_subtask(task)
            return result

        if not stat_report.is_file:
            self.logger.debug(
                "Ignoring special file (link, chrdev, blkdev, fifo, socket, door)."
            )
            return result

        magic = config.get_magic(self.path)
        mime_type = config.get_mime_type(self.path)
        self.logger.debug("Detected file-magic", magic=magic, _verbosity=2)

        magic_report = FileMagicReport(magic=magic, mime_type=mime_type)
        result.add_report(magic_report)

        hash_report = HashReport.from_path(self.path)
        result.add_report(hash_report)

        if stat_report.size == 0:
            self.logger.debug("Ignoring empty file")
            return result

        should_skip_file = any(
            magic.startswith(pattern) for pattern in config.skip_magic
        )

        if should_skip_file:
            self.logger.debug("Ignoring file based on magic", magic=magic)
            return result

        return self.dispatch_chunk_extraction(config, result)

    def dispatch_chunk_extraction(
        self, config: ExtractionConfig, result: "TaskResult"
    ) -> "TaskResult":
        with File.from_path(self.path) as file:
            size = len(file)
            all_chunks = search_chunks(file, size, config.handlers, result.add_report)

        outer_chunks = remove_inner_chunks(all_chunks)
        unknown_chunks = calculate_unknown_chunks(outer_chunks, size)

        unknown_handler = UnknownHandler(
            do_entropy_calculation=self.depth < config.entropy_depth,
            do_entropy_plot=config.entropy_plot,
        )

        is_whole_file_chunk = len(unknown_chunks) + len(outer_chunks) == 1
        if is_whole_file_chunk:
            if outer_chunks:
                [chunk] = outer_chunks
                task = self.create_whole_file_task(config, chunk.handler)
            else:
                task = self.create_whole_file_task(config, unknown_handler)
            result.add_subtask(task)
            return result

        for chunk in outer_chunks:
            task = self.create_task(config, chunk, chunk.handler)
            result.add_subtask(task)

        for chunk in unknown_chunks:
            task = self.create_task(config, chunk, unknown_handler)
            result.add_subtask(task)

        return result

    def create_whole_file_task(
        self, config: ExtractionConfig, handler: Handler
    ) -> "FileTask":
        keep_input = handler.INPUT_FILE_KEPT or config.keep_extracted_chunks
        return FileTask(
            path=self.path,
            depth=self.depth,
            chunk_id=self.chunk_id,
            handler=handler,
            keep_input=keep_input,
        )

    def create_task(
        self, config: ExtractionConfig, chunk: Chunk, handler: Handler
    ) -> Task:
        assert handler.CARVE_CHUNKS, "Direct chunk extraction is not yet supported"
        task = CarveTask(
            path=self.path,
            depth=self.depth,
            chunk=chunk,
            handler=handler,
            chunk_id=self.chunk_id,
        )
        return task


class UnknownHandler(Handler):
    """Describes what happens with unknown file types.

    Calculates entropy.
    """

    def __reduce__(self):
        # Makes Handler singletons pickleable
        return self.__class__, (self.do_entropy_calculation, self.do_entropy_plot)

    NAME = "unknown"
    # what will happen to carved chunk files after extraction?
    CARVED_FILE_KEPT = True
    # what will happen to extracted input files?
    INPUT_FILE_KEPT = True

    def __init__(self, do_entropy_calculation: bool, do_entropy_plot: bool):
        super().__init__()
        self.do_entropy_calculation = do_entropy_calculation
        self.do_entropy_plot = do_entropy_plot

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ValidChunk]:
        raise NotImplementedError("Unknown chunks are calculated differently")

    def extract(self, inpath: Path, outdir: Path):
        if self.do_entropy_calculation:
            calculate_entropy(inpath, draw_plot=self.do_entropy_plot)


class DirTask(Task):
    def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
        for path in self.path.iterdir():
            result.add_subtask(
                ClassifierTask(
                    chunk_id=self.chunk_id,
                    path=path,
                    depth=self.depth + 1,
                )
            )
        return result


@attr.define(frozen=True)
class FileTask(Task):
    """A generic task working on a resource backed vaguely by the file system"""

    handler: Handler
    keep_input: bool = True

    def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
        extract_dir = config.get_extract_dir_for(self.path)
        handler = self.handler
        try:
            # TODO: handle encrypted chunks in handlers (currently: rar & zip)
            handler.extract(self.path, extract_dir)

        except ExtractError as e:
            for report in e.reports:
                result.add_report(report)

        except Exception as exc:
            self.logger.exception("Unknown error happened while extracting file")
            result.add_report(UnknownError(exception=exc))

        else:
            # we do it only when no exception happened - aiding debugging failures
            if not self.keep_input:
                self.logger.debug("Removing extracted path")
                self.path.unlink()
                result.add_report(DeletedInputReport())

        # we want to get consistent partial output even in case of unforeseen problems
        fix_extracted_directory(extract_dir, result.add_report)

        if extract_dir.exists():
            result.add_subtask(
                DirTask(
                    chunk_id=self.chunk_id,
                    path=extract_dir,
                    depth=self.depth + 1,
                )
            )
        return result


@attr.define(frozen=True)
class CarveTask(Task):
    """Extracts recognized part of a file"""

    chunk: Chunk
    handler: Handler

    def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
        chunk = self.chunk
        carve_dir = config.get_extract_dir_for(self.path)
        with File.from_path(self.path) as file:
            carved_path = carve_chunk(carve_dir, file, chunk, self.handler)

        task = FileTask(
            path=carved_path,
            handler=self.handler,
            depth=self.depth + 1,
            keep_input=config.keep_extracted_chunks or self.handler.CARVED_FILE_KEPT,
            chunk_id="",
        )

        result.add_subtask(task)
        return result


# TODO: decide if it is worth implementing it
# @attr.define(frozen=True)
# class ChunkTask(Task):
#     """Directly (without carving!) processes parts of a file"""
#
#     chunk: ValidChunk  # TODO: use Chunk, eliminate ValidChunk, UnknownChunk
#
#     def run(self, config: ExtractionConfig, result: "TaskResult") -> "TaskResult":
#         # TODO: define and call Handler interface for extracting chunk directly, skipping the carving step
#         return result


@attr.define
class TaskResult:
    task: Task
    reports: List[Report] = attr.field(factory=list)
    subtasks: List[Task] = attr.field(factory=list)

    def add_report(self, report: Report):
        self.reports.append(report)

    def add_subtask(self, task: Task):
        self.subtasks.append(task)


@attr.define
class ProcessResult:
    results: List[TaskResult] = attr.field(factory=list)

    @property
    def errors(self) -> List[ErrorReport]:
        reports = itertools.chain.from_iterable(r.reports for r in self.results)
        interesting_reports = (
            r for r in reports if isinstance(r, (ErrorReport, ChunkReport))
        )
        errors = []
        for report in interesting_reports:
            if isinstance(report, ErrorReport):
                errors.append(report)
            else:
                errors.extend(
                    r for r in report.extraction_reports if isinstance(r, ErrorReport)
                )
        return errors

    def register(self, result: TaskResult):
        self.results.append(result)

    def to_json(self, indent="  "):
        return json.dumps(self.results, cls=_JSONEncoder, indent=indent)


class _JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if attr.has(type(obj)):
            extend_attr_output = True
            attr_output = attr.asdict(obj, recurse=not extend_attr_output)
            attr_output["__typename__"] = obj.__class__.__name__
            return attr_output

        if isinstance(obj, Enum):
            return obj.name

        if isinstance(obj, Path):
            return str(obj)

        if isinstance(obj, bytes):
            try:
                return obj.decode()
            except UnicodeDecodeError:
                return str(obj)

        if isinstance(obj, Handler):
            return str(obj.__class__)

        logger.error(f"JSONEncoder met a non-JSON encodable value: {obj}")
        # the usual fail path of custom JSONEncoders is to call the parent and let it fail
        #     return json.JSONEncoder.default(self, obj)
        # instead of failing, just return something usable
        return f"Non-JSON encodable value: {obj}"
