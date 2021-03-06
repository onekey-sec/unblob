import binascii
import io

from attr import dataclass
from lark.lark import Lark
from lark.visitors import Discard, Transformer


def unhex(hexdump: str) -> bytes:
    """Unparses hexdump back to binary representation.

    In addition to basic parsing the following extra features are supported:

    * line comments starting with ``#``
    * squeezing (repetition of previous line) indicated via ``*`` (see: man 1 hexdump)

    Relative position of data is kept in the result object. This means
    that the offset indicator at the beginning of each line is
    significant, each line will be stored at the position indicated
    relative to the start position.

    The printable ASCII column is discarded during parsing.

    NOTE: all lines MUST contain exactly 16 bytes, except the last line, which can have less.
    """
    parsed = _hexdump_parser.parse(hexdump)
    return _HexDumpToBin().transform(parsed)


BYTES_PER_LINE = 16


_hexdump_parser = Lark(
    """
    %import common.NEWLINE
    %import common.HEXDIGIT

    start:   line (_NEWLINE line)* _NEWLINE?
    line:    address [_SEPARATOR hex _SEPARATOR "|"? ascii "|"?]  -> canonical
             | SQUEEZE                                            -> squeezed
    address: HEXDIGIT+                                            -> join
    hex:     HEXDIGIT+ (_SPACE* HEXDIGIT)+                        -> join
    ascii:   CHAR+                                                -> join
    CHAR:    /./
    SQUEEZE: "*"

    _SEPARATOR: ": " | "  "
    _SPACE:     " "
    _NEWLINE:   NEWLINE
"""
)


@dataclass
class _HexdumpLine:
    offset: int
    data: bytes

    @classmethod
    def from_bytes(cls, offset, data):
        offset = int.from_bytes(binascii.unhexlify(offset), byteorder="big")
        data = binascii.unhexlify(data) if data else b""
        return cls(offset, data)

    def __len__(self):
        return len(self.data)


class _HexDumpToBin(Transformer):
    def __init__(self):
        super().__init__(visit_tokens=False)
        self._last_line = None
        self._squeezing = False

    def join(self, s):
        return "".join(s.strip() for s in s)

    def canonical(self, s):
        line = _HexdumpLine.from_bytes(s[0], s[1])
        if self._squeezing:
            self._squeezing = False
            line = self._squeeze_in_data(line)
        self._last_line = line
        return self._last_line

    def _squeeze_in_data(self, line: _HexdumpLine) -> _HexdumpLine:
        if not self._last_line:
            raise ValueError("Squeezed line cannot be the first line in a hexdump")

        assert len(self._last_line) % BYTES_PER_LINE == 0

        delta = line.offset - (self._last_line.offset + len(self._last_line))
        count = delta // BYTES_PER_LINE

        return _HexdumpLine(
            self._last_line.offset + len(self._last_line),
            self._last_line.data[-BYTES_PER_LINE:] * count + line.data,
        )

    def squeezed(self, _s):
        self._squeezing = True
        return Discard

    def start(self, s):
        rv = io.BytesIO()
        for line in s:
            rv.write(line.data)

        return rv.getvalue()
