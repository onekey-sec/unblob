import pytest

from unblob.file_utils import InvalidInputFormat
from unblob.finder import build_hyperscan_database, search_chunks
from unblob.models import File, Handler, HexString, Regex, ValidChunk
from unblob.parser import InvalidHexString


class TestHandlerA(Handler):
    NAME = "handlerA"
    PATTERNS = [Regex("A")]

    def calculate_chunk(self, file, start_offset: int):
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 5)


class TestHandlerB(Handler):
    NAME = "handlerB"
    PATTERNS = [Regex("BB"), Regex("BC")]

    PATTERN_MATCH_OFFSET = -1

    def calculate_chunk(self, file, start_offset: int):
        return ValidChunk(start_offset=start_offset, end_offset=start_offset + 10)


class TestHandlerD(Handler):
    NAME = "handlerD"
    PATTERNS = [Regex("D"), HexString("ff ff ff")]

    def calculate_chunk(self, file, start_offset: int):
        return None


class TestHandlerEof(Handler):
    NAME = "handlerEOF"
    PATTERNS = [Regex("EOF")]

    def calculate_chunk(self, file, start_offset: int):
        raise EOFError()


class TestHandlerInvalid(Handler):
    NAME = "handlerInvalid"
    PATTERNS = [Regex("I")]

    def calculate_chunk(self, file, start_offset: int):
        raise InvalidInputFormat()


class TestHandlerExc(Handler):
    NAME = "handlerEXC"
    PATTERNS = [Regex("EXC")]

    def calculate_chunk(self, file, start_offset: int):
        raise Exception("Error")


def test_build_hyperscan_database():
    db, handler_map = build_hyperscan_database((TestHandlerA, TestHandlerB))
    matches = []
    db.scan(
        [bytearray(b"A123456789BB")],
        match_event_handler=lambda pattern_id, start, end, flags, m: m.append(
            (pattern_id, start, end)
        ),
        context=matches,
    )

    assert len(handler_map) == 3

    assert len(matches) == 2
    assert isinstance(handler_map[matches[0][0]], TestHandlerA)
    assert isinstance(handler_map[matches[1][0]], TestHandlerB)
    assert matches[0][1] == 0
    assert matches[1][1] == 10


def test_db_and_handler_map_instances_are_cached():
    db1, handler_map1 = build_hyperscan_database((TestHandlerA, TestHandlerB))
    db2, handler_map2 = build_hyperscan_database((TestHandlerA, TestHandlerB))
    db3, handler_map3 = build_hyperscan_database((TestHandlerA,))
    assert db1 is db2
    assert handler_map1 is handler_map2
    assert db1 is not db3
    assert handler_map1 is not handler_map3


def test_invalid_hexstring_pattern_raises():
    class InvalidHandler(Handler):
        NAME = "InvalidHandler"
        PATTERNS = [HexString("invalid pattern")]

        def calculate_chunk(self, file, start_offset: int):
            pass

    with pytest.raises(InvalidHexString):
        build_hyperscan_database(tuple([TestHandlerA, TestHandlerB, InvalidHandler]))


@pytest.mark.parametrize(
    "content, expected_chunks",
    [
        pytest.param(b"00A23450", [ValidChunk(2, 7)], id="single-chunk"),
        pytest.param(
            b"0BB34A678900", [ValidChunk(0, 10)], id="chunk-with-relative-match-offset"
        ),
        pytest.param(
            b"A23450BB3456789",
            [ValidChunk(0, 5), ValidChunk(5, 15)],
            id="multiple-chunk",
        ),
        pytest.param(b"0BC34A67890", [ValidChunk(0, 10)], id="inner-chunk-ignored"),
        pytest.param(
            b"0BC34A67890A2345",
            [ValidChunk(0, 10), ValidChunk(11, 16)],
            id="inner-chunk-ignored-scan-continues",
        ),
        pytest.param(b"A23450BB34", [ValidChunk(0, 5)], id="overflowing-chunk-ignored"),
        pytest.param(
            b"0BBA2345",
            [ValidChunk(3, 8)],
            id="overflowing-chunk-ignored-scan-continues",
        ),
        pytest.param(b"A2345", [ValidChunk(0, 5)], id="whole-file-chunk"),
        pytest.param(b"00000A2345", [ValidChunk(5, 10)], id="chunk-till-end-of-file"),
        pytest.param(
            b"BB34A678900",
            [ValidChunk(4, 9)],
            id="chunk-with-invalid-relative-match-offset-ignored",
        ),
        pytest.param(b"00D00A2345", [ValidChunk(5, 10)], id="invalid-chunk-ignored"),
        pytest.param(b"EOFA2345", [ValidChunk(3, 8)], id="eof-ignored-scan-continues"),
        pytest.param(
            b"IA2345", [ValidChunk(1, 6)], id="invalid-chunk-ignored-scan-continues"
        ),
        pytest.param(
            b"EXCA2345", [ValidChunk(3, 8)], id="exception-ignored-scan-continues"
        ),
    ],
)
def test_search_chunks(content, expected_chunks, task_result):
    file = File.from_bytes(content)

    handlers = (
        TestHandlerA,
        TestHandlerB,
        TestHandlerD,
        TestHandlerEof,
        TestHandlerInvalid,
        TestHandlerExc,
    )

    chunks = search_chunks(file, len(content), handlers, task_result.add_report)

    assert chunks == expected_chunks
