import io
from pathlib import Path
from typing import Dict, List, Iterable
import yara
from .models import YaraMatchResult
from .handlers import Handler


_YARA_RULE_TEMPLATE = """
rule {NAME}
{{
    {YARA_RULE}
}}
"""


def _make_yara_rules(handlers: Iterable[Handler]):
    all_yara_rules = "\n".join(
        _YARA_RULE_TEMPLATE.format(NAME=h.NAME, YARA_RULE=h.YARA_RULE.strip())
        for h in handlers
    )
    print("Searching with yara rules:", all_yara_rules)
    compiled_rules = yara.compile(source=all_yara_rules, includes=False)
    return compiled_rules


def search_chunks(
    handlers: Dict[str, Handler], full_path: Path
) -> List[YaraMatchResult]:
    yara_rules = _make_yara_rules(handlers.values())
    # YARA uses a memory mapped file internally when given a path
    yara_matches: List[yara.Match] = yara_rules.match(str(full_path), timeout=60)

    yara_results = []
    for match in yara_matches:
        handler = handlers[match.rule]
        yara_res = YaraMatchResult(handler=handler, match=match)
        yara_results.append(yara_res)

    return yara_results
