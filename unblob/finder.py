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

from .file_utils import LimitedStartReader
from .handlers import ALL_HANDLERS_BY_PRIORITY
from .logging import noformat
from .models import Handler, ValidChunk, YaraMatchResult
from .state import exit_code_var

logger = get_logger()


_YARA_RULE_TEMPLATE = """
rule {NAME}
{{
    {YARA_RULE}
}}
"""


def search_chunks_by_priority(  # noqa: C901
    path: Path, file: io.BufferedReader, file_size: int
) -> List[ValidChunk]:
    """Search all ValidChunks within the file.
    Collect all the registered handlers by priority, search for YARA patterns and run
    Handler.calculate_chunk() on the found matches.
    We don't deal with offset within already found ValidChunks and invalid chunks are thrown away.
    """
    all_chunks = []

    for priority_level, handler_classes in enumerate(ALL_HANDLERS_BY_PRIORITY, start=1):
        logger.info("Starting priority level", priority_level=noformat(priority_level))
        yara_rules = make_yara_rules(handler_classes)
        handler_map = make_handler_map(handler_classes)
        yara_results = search_yara_patterns(yara_rules, handler_map, path)

        for result in yara_results:
            handler, match = result.handler, result.match

            by_offset = itemgetter(0)
            sorted_match_strings = sorted(match.strings, key=by_offset)
            for offset, identifier, string_data in sorted_match_strings:
                real_offset = offset + handler.YARA_MATCH_OFFSET

                # Skip chunk calculation if the match is found too early in the file,
                # leading to a negative real offset once YARA_MATCH_OFFSET is applied.
                if real_offset < 0:
                    continue

                # Skip chunk calculation if this would start inside another one,
                # similar to remove_inner_chunks, but before we even begin calculating.
                if any(chunk.contains_offset(real_offset) for chunk in all_chunks):
                    continue

                logger.info(
                    "Calculating chunk for YARA match",
                    start_offset=offset,
                    real_offset=real_offset,
                    identifier=identifier,
                )

                limited_reader = LimitedStartReader(file, real_offset)
                try:
                    chunk = handler.calculate_chunk(limited_reader, real_offset)
                except EOFError as exc:
                    logger.debug(
                        "File ends before header could be read",
                        exc_info=exc,
                        handler=handler.NAME,
                    )
                    continue
                except Exception as exc:
                    exit_code_var.set(1)
                    logger.error(
                        "Unhandled Exception during chunk calculation", exc_info=exc
                    )
                    continue

                # We found some random bytes this handler couldn't parse
                if chunk is None:
                    continue

                if chunk.end_offset > file_size or chunk.start_offset < 0:
                    exit_code_var.set(1)
                    logger.error("Chunk overflows file", chunk=chunk)
                    continue

                chunk.handler = handler
                logger.info("Found valid chunk", chunk=chunk, handler=handler.NAME)
                all_chunks.append(chunk)

    return all_chunks


@lru_cache
def make_yara_rules(handlers: Tuple[Type[Handler], ...]):
    """Make yara.Rule by concatenating all handlers yara rules and compiling them."""
    all_yara_rules = "\n".join(
        _YARA_RULE_TEMPLATE.format(NAME=h.NAME, YARA_RULE=h.YARA_RULE.strip())
        for h in handlers
    )
    logger.debug("Compiled YARA rules", rules=all_yara_rules)
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
    yara_matches: List[yara.Match] = yara_rules.match(str(full_path), timeout=60)

    yara_results = []
    for match in yara_matches:
        handler = handler_map[match.rule]
        yara_res = YaraMatchResult(handler=handler, match=match)
        yara_results.append(yara_res)

    if yara_results:
        logger.info("Found YARA results", count=noformat(len(yara_results)))

    return yara_results
