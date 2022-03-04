"""
Searching Chunk related functions.
The main "entry point" is search_chunks_by_priority.
"""
import io
from functools import lru_cache
from operator import itemgetter
from pathlib import Path
from typing import Dict, List, Tuple, Type

import yara
from structlog import get_logger

from .file_utils import InvalidInputFormat, LimitedStartReader
from .handlers import Handlers
from .logging import noformat
from .models import Handler, TaskResult, ValidChunk, YaraMatchResult
from .report import CalculateChunkExceptionReport

logger = get_logger()


_YARA_RULE_TEMPLATE = """
rule {NAME}
{{
    {YARA_RULE}
}}
"""


def search_chunks_by_priority(  # noqa: C901
    path: Path,
    file: io.BufferedReader,
    file_size: int,
    handlers: Handlers,
    task_result: TaskResult,
) -> List[ValidChunk]:
    """Search all ValidChunks within the file.
    Collect all the registered handlers by priority, search for YARA patterns and run
    Handler.calculate_chunk() on the found matches.
    We don't deal with offset within already found ValidChunks and invalid chunks are thrown away.
    """
    all_chunks = []

    for priority_level, handler_classes in enumerate(handlers.by_priority, start=1):
        logger.debug("Starting priority level", priority_level=noformat(priority_level))
        yara_rules = make_yara_rules(handler_classes)
        handler_map = make_handler_map(handler_classes)
        yara_results = search_yara_patterns(yara_rules, handler_map, path)

        for result in yara_results:
            handler, match = result.handler, result.match

            by_offset = itemgetter(0)
            sorted_match_strings = sorted(match.strings, key=by_offset)
            for offset, identifier, _string_data in sorted_match_strings:
                real_offset = offset + handler.YARA_MATCH_OFFSET

                # Skip chunk calculation if the match is found too early in the file,
                # leading to a negative real offset once YARA_MATCH_OFFSET is applied.
                if real_offset < 0:
                    continue

                # Skip chunk calculation if this would start inside another one,
                # similar to remove_inner_chunks, but before we even begin calculating.
                if any(chunk.contains_offset(real_offset) for chunk in all_chunks):
                    logger.debug(
                        "Skip chunk calculation as pattern is inside an other chunk",
                        handler=handler.NAME,
                        offset=real_offset,
                        _verbosity=2,
                    )
                    continue

                logger.debug(
                    "Calculating chunk for YARA match",
                    start_offset=offset,
                    real_offset=real_offset,
                    identifier=identifier,
                    _verbosity=2,
                )

                limited_reader = LimitedStartReader(file, real_offset)
                try:
                    chunk = handler.calculate_chunk(limited_reader, real_offset)
                except InvalidInputFormat as exc:
                    logger.debug(
                        "File format is invalid",
                        exc_info=exc,
                        handler=handler.NAME,
                        _verbosity=2,
                    )
                    continue
                except EOFError as exc:
                    logger.debug(
                        "File ends before header could be read",
                        exc_info=exc,
                        handler=handler.NAME,
                        _verbosity=2,
                    )
                    continue
                except Exception as exc:
                    error_report = CalculateChunkExceptionReport(
                        handler=handler.NAME,
                        start_offset=real_offset,
                        exception=exc,
                    )
                    task_result.add_report(error_report)
                    logger.error(
                        "Unhandled Exception during chunk calculation",
                        **error_report.asdict()
                    )
                    continue

                # We found some random bytes this handler couldn't parse
                if chunk is None:
                    continue

                if chunk.end_offset > file_size:
                    logger.debug("Chunk overflows file", chunk=chunk, _verbosity=2)
                    continue

                chunk.handler = handler
                logger.debug(
                    "Found valid chunk", chunk=chunk, handler=handler.NAME, _verbosity=2
                )
                all_chunks.append(chunk)

        logger.debug("Ended priority level", priority_level=noformat(priority_level))

    return all_chunks


@lru_cache
def make_yara_rules(handlers: Tuple[Type[Handler], ...]):
    """Make yara.Rule by concatenating all handlers yara rules and compiling them."""
    all_yara_rules = "\n".join(
        _YARA_RULE_TEMPLATE.format(NAME=h.NAME, YARA_RULE=h.YARA_RULE.strip())
        for h in handlers
    )
    logger.debug("Compiled YARA rules", rules=all_yara_rules, _verbosity=3)
    compiled_rules = yara.compile(source=all_yara_rules, includes=False)
    return compiled_rules


@lru_cache
def make_handler_map(handler_classes: Tuple[Type[Handler], ...]) -> Dict[str, Handler]:
    return {h.NAME: h() for h in handler_classes}


def search_yara_patterns(
    yara_rules: yara.Rule, handler_map: Dict[str, Handler], full_path: Path
) -> List[YaraMatchResult]:
    """Search with the compiled YARA rules and identify the handler which defined the rule."""
    # YARA uses a memory mapped file internally when given a path
    yara_matches: List[yara.Match] = yara_rules.match(full_path.as_posix())

    yara_results = []
    for match in yara_matches:
        handler = handler_map[match.rule]
        yara_res = YaraMatchResult(handler=handler, match=match)
        yara_results.append(yara_res)

    if yara_results:
        logger.debug("Found YARA results", count=noformat(len(yara_results)))

    return yara_results
