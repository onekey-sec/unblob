"""
Searching Chunk related functions.
The main "entry point" is search_chunks_by_priority.
"""
from functools import lru_cache
from typing import List, Optional

import attr
from pyperscan import BlockDatabase, Flag, Pattern, Scan
from structlog import get_logger

from .file_utils import InvalidInputFormat, SeekError
from .handlers import Handlers
from .models import File, Handler, TaskResult, ValidChunk
from .parser import InvalidHexString
from .report import CalculateChunkExceptionReport

logger = get_logger()


@attr.define
class HyperscanMatchContext:
    file: File
    file_size: int
    all_chunks: List
    task_result: TaskResult


def _calculate_chunk(
    handler: Handler, file: File, real_offset, task_result: TaskResult
) -> Optional[ValidChunk]:

    file.seek(real_offset)
    try:
        return handler.calculate_chunk(file, real_offset)
    except InvalidInputFormat as exc:
        logger.debug(
            "File format is invalid",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except EOFError as exc:
        logger.debug(
            "File ends before header could be read",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except SeekError as exc:
        logger.debug(
            "Seek outside file during chunk calculation",
            exc_info=exc,
            handler=handler.NAME,
            _verbosity=2,
        )
    except Exception as exc:
        error_report = CalculateChunkExceptionReport(
            handler=handler.NAME,
            start_offset=real_offset,
            exception=exc,
        )
        task_result.add_report(error_report)
        logger.error(
            "Unhandled Exception during chunk calculation", **error_report.asdict()
        )


def _hyperscan_match(
    context: HyperscanMatchContext, handler: Handler, offset: int, end: int
) -> Scan:
    real_offset = offset + handler.PATTERN_MATCH_OFFSET

    if real_offset < 0:
        return Scan.Continue

    # Skip chunk calculation if this would start inside another one,
    # similar to remove_inner_chunks, but before we even begin calculating.
    if any(chunk.contains_offset(real_offset) for chunk in context.all_chunks):
        logger.debug(
            "Skip chunk calculation as pattern is inside an other chunk",
            handler=handler.NAME,
            offset=real_offset,
            _verbosity=2,
        )
        return Scan.Continue

    logger.debug(
        "Calculating chunk for pattern match",
        start_offset=offset,
        real_offset=real_offset,
        _verbosity=2,
    )

    chunk = _calculate_chunk(handler, context.file, real_offset, context.task_result)

    # We found some random bytes this handler couldn't parse
    if chunk is None:
        return Scan.Continue

    if chunk.end_offset > context.file_size:
        logger.debug("Chunk overflows file", chunk=chunk, _verbosity=2)
        return Scan.Continue

    chunk.handler = handler
    logger.debug("Found valid chunk", chunk=chunk, handler=handler.NAME, _verbosity=2)
    context.all_chunks.append(chunk)

    # Terminate scan if we match till the end of the file
    if chunk.end_offset == context.file_size:
        logger.debug("Chunk covers till end of the file", chunk=chunk)
        return Scan.Terminate

    return Scan.Continue


def search_chunks(  # noqa: C901
    file: File,
    file_size: int,
    handlers: Handlers,
    task_result: TaskResult,
) -> List[ValidChunk]:
    """Search all ValidChunks within the file.
    Search for patterns and run Handler.calculate_chunk() on the found matches.
    We don't deal with offset within already found ValidChunks and invalid chunks are thrown away.
    If chunk covers the whole file we stop any further search and processing.
    """
    all_chunks = []

    hyperscan_db = build_hyperscan_database(handlers)

    hyperscan_context = HyperscanMatchContext(
        file=file,
        file_size=file_size,
        all_chunks=all_chunks,
        task_result=task_result,
    )

    scanner = hyperscan_db.build(hyperscan_context, _hyperscan_match)

    try:
        if scanner.scan(file) == Scan.Terminate:
            logger.debug(
                "Scanning terminated as chunk matches till end of file",
            )
            return all_chunks
    except Exception as e:
        logger.error(
            "Error scanning for patterns",
            error=e,
        )

    logger.debug(
        "Ended searching for chunks",
        all_chunks=all_chunks,
    )

    return all_chunks


@lru_cache
def build_hyperscan_database(handlers: Handlers):
    patterns = []
    for handler_class in handlers:
        handler = handler_class()
        for pattern in handler.PATTERNS:
            try:
                patterns.append(
                    Pattern(
                        pattern.as_regex(),
                        Flag.SOM_LEFTMOST,
                        Flag.DOTALL,
                        tag=handler,
                    )
                )
            except InvalidHexString as e:
                logger.error(
                    "Invalid pattern",
                    handler=handler.NAME,
                    pattern=pattern,
                    error=str(e),
                )
                raise
    return BlockDatabase(*patterns)
