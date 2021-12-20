from pathlib import Path

from conftest import TestHandler

from unblob.finder import make_handler_map, make_yara_rules, search_yara_patterns


class TestHandler1(TestHandler):
    NAME = "handler1"
    YARA_RULE = r"""
        strings:
            $handler1_magic = { 21 3C }
        condition:
            $handler1_magic
    """


class TestHandler2(TestHandler):
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
    assert matches[0].strings == [(0, "$handler1_magic", b"!<")]
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
    assert result1.match.strings == [(0, "$handler1_magic", b"!<")]

    assert result2.handler is handler2
    assert result2.match.strings == [(10, "$tar_magic", b"ustar")]


def test_make_handler_map():
    handler_map = make_handler_map(tuple([TestHandler1, TestHandler2]))
    assert isinstance(handler_map["handler1"], TestHandler1)
    assert isinstance(handler_map["handler2"], TestHandler2)


def test_make_handler_map_instances_are_cached():
    handler_map1 = make_handler_map(tuple([TestHandler1, TestHandler2]))
    handler_map2 = make_handler_map(tuple([TestHandler1, TestHandler2]))
    assert handler_map1["handler1"] is handler_map2["handler1"]
    assert handler_map1["handler2"] is handler_map2["handler2"]
