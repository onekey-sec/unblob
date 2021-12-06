import io
from functools import lru_cache
from operator import itemgetter
from pathlib import Path
from typing import List, Tuple

import yara
from structlog import get_logger

from .file_utils import LimitedStartReader
from .handlers import Handler
from .logging import noformat
from .models import ValidChunk, YaraMatchResult
from .state import exit_code_var

logger = get_logger()


_YARA_RULE_TEMPLATE = """
rule {NAME}
{{
    {YARA_RULE}
}}
"""


@lru_cache
def _make_yara_rules(handlers: Tuple[Handler, ...]):
    all_yara_rules = "\n".join(
        _YARA_RULE_TEMPLATE.format(NAME=h.NAME, YARA_RULE=h.YARA_RULE.strip())
        for h in handlers
    )
    logger.debug("Compiled YARA rules", rules=all_yara_rules)
    compiled_rules = yara.compile(source=all_yara_rules, includes=False)
    return compiled_rules


def search_yara_matches(
    handlers: Tuple[Handler, ...], full_path: Path
) -> List[YaraMatchResult]:
    handlers_map = {h.NAME: h for h in handlers}
    yara_rules = _make_yara_rules(handlers)
    # YARA uses a memory mapped file internally when given a path
    yara_matches: List[yara.Match] = yara_rules.match(str(full_path), timeout=60)

    yara_results = []
    for match in yara_matches:
        handler = handlers_map[match.rule]
        yara_res = YaraMatchResult(handler=handler, match=match)
        yara_results.append(yara_res)

    return yara_results


def search_chunks(  # noqa: C901
    handlers: Tuple[Handler, ...], path: Path, file: io.BufferedReader, file_size: int
) -> List[ValidChunk]:
    all_chunks = []

    yara_results = search_yara_matches(handlers, path)

    if yara_results:
        logger.info("Found YARA results", count=noformat(len(yara_results)))

    for result in yara_results:
        handler = result.handler
        match = result.match
        sorted_matches = sorted(match.strings, key=itemgetter(0))
        for offset, identifier, string_data in sorted_matches:
            real_offset = offset + handler.YARA_MATCH_OFFSET

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
