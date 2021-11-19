import io
from typing import Callable, List, Union

from ....file_utils import round_up, snull
from ....models import UnknownChunk, ValidChunk

CPIO_TRAILER_NAME = b"TRAILER!!!"
MAX_LINUX_PATH_LENGTH = 0x1000


class _CPIOHandlerBase:
    """A common base for all CPIO formats
    The format should be parsed the same, there are small differences how to calculate
    file and filename sizes padding and conversion from octal / hex.
    """

    NAME: str
    YARA_RULE: str

    _PAD_ALIGN: int
    _HEADER_PARSER: Callable

    @classmethod
    def calculate_chunk(
        cls, file: io.BufferedReader, start_offset: int
    ) -> Union[ValidChunk, UnknownChunk]:
        file.seek(start_offset)
        offset = start_offset
        while True:
            file.seek(offset, io.SEEK_SET)
            header = cls._HEADER_PARSER(file)
            c_filesize = cls._calculate_file_size(header)
            c_namesize = cls._calculate_name_size(header)

            # heuristics 1: check the filename
            if c_namesize > MAX_LINUX_PATH_LENGTH:
                return UnknownChunk(
                    start_offset=start_offset, reason="Invalid CPIO header"
                )

            if c_namesize > 0:
                file.seek(offset + len(header), io.SEEK_SET)
                tmp_filename = file.read(c_namesize)

                # heuristics 2: check that filename is null-byte terminated
                if not tmp_filename.endswith(b"\x00"):
                    return UnknownChunk(
                        start_offset=start_offset, reason="Invalid CPIO header"
                    )

                filename = snull(tmp_filename)

                if filename == CPIO_TRAILER_NAME:
                    offset += cls._pad_content(header, c_filesize, c_namesize)
                    break

            # Rounding up the total of the header size, and the c_filesize, again. Because
            # some CPIO implementations don't align the first chunk, but do align the 2nd.
            # In theory, with a "normal" CPIO file, we should just be aligned on the
            # 4-byte boundary already, but if we are not for some reason, then we just
            # need to round up again.
            offset += cls._pad_content(header, c_filesize, c_namesize)

        return ValidChunk(
            start_offset=start_offset,
            end_offset=offset,
        )

    @classmethod
    def _pad_content(cls, header, c_filesize: int, c_namesize: int) -> int:
        """Pad header and content with 4 bytes."""
        padded_header = round_up(len(header), cls._PAD_ALIGN)
        padded_content = round_up(c_filesize + c_namesize, cls._PAD_ALIGN)
        return padded_header + padded_content

    @staticmethod
    def _calculate_file_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def _calculate_name_size(header) -> int:
        raise NotImplementedError

    @staticmethod
    def make_extract_command(inpath: str, outdir: str) -> List[str]:
        return ["7z", "x", "-y", inpath, f"-o{outdir}"]
