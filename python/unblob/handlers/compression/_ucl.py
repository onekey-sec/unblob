END_OF_STREAM_MARKER = 0xFF_FF_FF_FF


class BitReader:
    def __init__(self, data: bytes, start: int = 0):
        self.data = data
        self.index = start  # index in the data (byte-wise)
        self.bb = 0  # bit buffer
        self.bc = 0  # number of bits remaining in the buffer

    def get_bit(self) -> int:
        """Return the next bit from the data stream (0 or 1). When the bit buffer is empty, loads the next byte."""
        if self.bc == 0:
            if self.index >= len(self.data):
                raise ValueError("Unexpected end of data while reading bit")
            self.bb = self.data[self.index]
            self.index += 1
            self.bc = 8
        self.bc -= 1
        return (self.bb >> self.bc) & 1

    def read_byte(self) -> int:
        """Read and return the next full byte from the data stream. This does not take into account any bits already buffered."""
        if self.index >= len(self.data):
            raise ValueError("Unexpected end of data while reading byte")
        b = self.data[self.index]
        self.index += 1
        return b


class UCLDecompressor:
    def __init__(self):
        self._reader: BitReader = BitReader(b"")
        self._output: bytearray = bytearray()
        self._last_match_offset: int = -1
        self._match_offset: int = -1
        self._match_length: int = -1

    def _process_literal_run(self) -> None:
        """Process a run of literal bytes while the next bit is 1."""
        while self._reader.get_bit():
            self._output.append(self._reader.read_byte())

    def _decode_match_offset(self) -> int:
        """Decode the match offset value from the bit stream."""
        match_offset = 1
        while True:
            match_offset = (match_offset << 1) + self._reader.get_bit()
            if self._reader.get_bit() == 1:
                break
        return match_offset

    def _decode_match_length(self) -> int:
        """Decode the match length value from the bit stream."""
        # Get a two-bit base for the match length
        match_length = (self._reader.get_bit() << 1) + self._reader.get_bit()

        if match_length == 0:
            match_length += 1
            # Read extra bits until a terminating 1 is encountered
            while True:
                match_length = (match_length << 1) + self._reader.get_bit()
                if self._reader.get_bit() == 1:
                    break
            match_length += 2

        # If the match offset is large, add an extra byte to the length.
        if self._match_offset > 0xD00:
            match_length += 1

        return match_length

    def _copy_match_data(self) -> None:
        """Copy match data from the already decompressed output."""
        match_index = len(self._output) - self._match_offset
        if match_index < 0:
            raise ValueError("Invalid match offset")

        # Copy one byte unconditionally
        self._output.append(self._output[match_index])
        match_index += 1

        # Then copy match_length bytes (the regions may overlap)
        for _ in range(self._match_length):
            self._output.append(self._output[match_index])
            match_index += 1

    def decompress(self, compressed: bytes) -> bytes:
        """UCL decompression using NRV2B mode."""
        self._reader = BitReader(compressed, start=0)
        self._output = bytearray()
        self._last_match_offset = 1

        while True:
            self._process_literal_run()
            self._match_offset = self._decode_match_offset()

            if self._match_offset == 2:
                self._match_offset = self._last_match_offset
            else:
                # Read an extra byte to complete the offset.
                self._match_offset = (
                    self._match_offset - 3
                ) * 256 + self._reader.read_byte()
                if self._match_offset == END_OF_STREAM_MARKER:
                    break
                self._match_offset += 1
                self._last_match_offset = self._match_offset

            self._match_length = self._decode_match_length()
            self._copy_match_data()

        return bytes(self._output)
