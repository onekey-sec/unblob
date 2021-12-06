from pathlib import Path

from unblob.finder import make_yara_rules, search_yara_patterns
from unblob.models import Handler


class _BaseTestHandler(Handler):
    def calculate_chunk(self, *args, **kwargs):
        pass

    @staticmethod
    def make_extract_command(*args, **kwargs):
        return []


class TestHandler1(_BaseTestHandler):
    NAME = "handler1"
    YARA_RULE = r"""
        strings:
            $magic = { 21 3C }
        condition:
            $magic
    """


class TestHandler2(_BaseTestHandler):
    NAME = "handler2"
    YARA_RULE = r"""
        strings:
            $tar_magic = { 75 73 74 61 72 }
        condition:
            $tar_magic
    """


def test_make_yara_rules():
    rules = make_yara_rules(tuple([TestHandler1, TestHandler2]))
    matches = rules.match(data=b"!<        ustar")
    assert len(matches) == 2
    assert matches[0].strings == [(0, "$magic", b"!<")]
    assert matches[1].strings == [(10, "$tar_magic", b"ustar")]


def test_search_yara_patterns(tmp_path: Path):
    handler1 = TestHandler1()
    handler2 = TestHandler2
    rules = make_yara_rules(tuple([TestHandler1, TestHandler2]))
    handler_map = {"handler1": handler1, "handler2": handler2}
    test_file = tmp_path / "test_file"
    test_file.write_bytes(b"!<        ustar")
    results = search_yara_patterns(rules, handler_map, test_file)

    assert len(results) == 2
    result1, result2 = results

    assert result1.handler is handler1
    assert result1.match.strings == [(0, "$magic", b"!<")]

    assert result2.handler is handler2
    assert result2.match.strings == [(10, "$tar_magic", b"ustar")]
