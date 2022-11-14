import attr
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


class TestHandlerForward(Handler):
    """Matches stuff between parens: (whatever)

    Matches the initial ( and finds the next ) as chunk end.
    """

    NAME = "handlerEXC"
    PATTERNS = [Regex("[(]")]

    def calculate_chunk(self, file, start_offset: int):
        end_offset = file.find(b")", start_offset)
        assert end_offset >= 0
        return ValidChunk(start_offset, end_offset + 1)


class TestHandlerBackward(Handler):
    """Matches stuff between square brackets: [whatever]

    Matches the closing ] and finds the previous [ as chunk start.

    This is not a common strategy, but can be a valid/more efficient strategy in some cases
    (e.g. ZIP files).
    """

    NAME = "handlerEXC"
    PATTERNS = [Regex("]")]

    def calculate_chunk(self, file, start_offset: int):
        end_offset = start_offset
        start_offset = file.rfind(b"[", 0, end_offset)
        assert start_offset >= 0
        return ValidChunk(start_offset, end_offset + 1)


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
            b"0BB34X678900", [ValidChunk(0, 10)], id="chunk-with-relative-match-offset"
        ),
        pytest.param(
            b"A23450BB3456789",
            [ValidChunk(0, 5), ValidChunk(5, 15)],
            id="multiple-chunk",
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
        pytest.param(
            b"(.....[overlap]......)",
            # ^            [^ - this pattern match is optimized away]
            # 0123456789012345678901
            [ValidChunk(0, 22)],
            id="internal-chunk-whole-file-match-optimization",
        ),
        pytest.param(
            b"[.....(overlap)......]",
            #       ^              ^ backward matched second, the internal chunk is already there
            # 0123456789012345678901
            [ValidChunk(0, 22), ValidChunk(6, 15)],
            id="internal-chunk-whole-file-match-optimization-does-not-work-for-backward-match",
        ),
        pytest.param(
            b"[zip(..]zlib)",
            #     ^  ^
            # 0123456789012
            [ValidChunk(0, 8), ValidChunk(4, 13)],
            id="overlapping-chunks-backward-first",
        ),
        pytest.param(
            b"(zlib[..)zip]",
            # ^           ^
            # 01234567890123
            [ValidChunk(0, 9), ValidChunk(5, 13)],
            id="overlapping-chunks-backward-second",
        ),
        pytest.param(
            b"((AAA(((..).",
            # ^ ^
            # 01234567890123456789
            [ValidChunk(0, 11), ValidChunk(2, 7)],
            id="internal-matches-of-same-handler-are-optimized-away",
            # An extra at the end is needed, because whole file chunks are
            # stopping the pattern match.
            #
            # This optimization is intended for containers, like tar, cpio, ...
            # where we have many file headers and the same - well determined -
            # end for all of the file headers.
            #
            # Unfortunately it is possible only for forward handlers,
            # where the pattern is at the beginning of the structure, not for
            # something like zip, which we can better match from the end.
            #
            # It is also somewhat questionable if we want it generally,
            # as e.g. for HandlerA it will result matching only a single A chunk
            # while in fact there are 3 overlapping matches here (2-7, 3-8, 4-9),
            # but we just drop the last 2.
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
        TestHandlerForward,
        TestHandlerBackward,
    )

    chunks = search_chunks(file, len(content), handlers, task_result)

    assert len(chunks) == len(expected_chunks)

    # chunks are sorted by the pattern position, which in general do not match the chunk start
    # when processed with a "backward" handler, it can come even later than another match
    chunks = sorted(chunks, key=lambda chunk: (chunk.start_offset, chunk.end_offset))

    for expected_chunk, chunk in zip(expected_chunks, chunks):
        assert attr.evolve(chunk, id="") == attr.evolve(expected_chunk, id="")
