import gzip

from ...file_utils import DEFAULT_BUFSIZE

# pyright: reportGeneralTypeIssues=false


class SingleMemberGzipReader(gzip._GzipReader):  # noqa: SLF001
    def read_header(self):
        self._init_read()
        return self._read_gzip_header()

    def read(self):
        uncompress = b""

        while True:
            buf = self._fp.read(DEFAULT_BUFSIZE)

            uncompress = self._decompressor.decompress(buf, DEFAULT_BUFSIZE)
            self._fp.prepend(self._decompressor.unconsumed_tail)
            self._fp.prepend(self._decompressor.unused_data)

            if uncompress != b"":
                break
            if buf == b"":
                raise EOFError(
                    "Compressed file ended before the "
                    "end-of-stream marker was reached"
                )

        self._add_read_data(uncompress)

        return uncompress

    def read_until_eof(self):
        while not self._decompressor.eof:
            self.read()

    @property
    def unused_data(self):
        return self._decompressor.unused_data
