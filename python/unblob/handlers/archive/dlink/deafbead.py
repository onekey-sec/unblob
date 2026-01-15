from __future__ import annotations

import gzip
import io
from pathlib import Path, PureWindowsPath

from unblob.file_utils import Endian, File, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    HandlerDoc,
    HandlerType,
    HexString,
    StructHandler,
    ValidChunk,
)

C_DEFINITIONS = r"""
    typedef struct deafbead_header {
        uint32 magic;           /* "DE AF BE AD" */
    } deafbead_header_t;

    typedef struct deafbead_dir {
        uint8  magic;           /* "86" */
        uint16 name_len;
        char   name[name_len];
    } deafbead_dir_t;

    typedef struct deafbead_file {
        uint8  magic;           /* "87" */
        uint16 name_len;
        char   name[name_len];
        uint32 file_size;
        char   file_contents[file_size];
    } deafbead_file_t;
"""
DIR_MAGIC = b"\x86"
FILE_MAGIC = b"\x87"
VALID_MAGICS = {DIR_MAGIC, FILE_MAGIC}
HEADER_LEN = 4


class DeafBeadExtractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITIONS)

    def extract(self, inpath: Path, outdir: Path):
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            file.seek(HEADER_LEN)
            while (magic := file.read(1)) in VALID_MAGICS:
                file.seek(-1, io.SEEK_CUR)  # go back to read the full struct
                if magic == DIR_MAGIC:
                    self._handle_dir(file, fs)
                elif magic == FILE_MAGIC:
                    self._handle_file(file, fs)

    def _handle_dir(self, file: File, fs: FileSystem):
        dir_header = self._struct_parser.parse("deafbead_dir_t", file, Endian.LITTLE)
        fs.mkdir(self._convert_path(dir_header.name))

    def _handle_file(self, file: File, fs: FileSystem):
        file_header = self._struct_parser.parse("deafbead_file_t", file, Endian.LITTLE)
        try:
            decompressed = gzip.decompress(file_header.file_contents)
            fs.write_bytes(self._convert_path(file_header.name), decompressed)
        except gzip.BadGzipFile as error:
            raise InvalidInputFormat("Invalid GZIP file") from error

    @staticmethod
    def _convert_path(path_entry: bytes) -> Path:
        decoded_path = path_entry.decode("utf-8", errors="replace")
        if "\\" in decoded_path:  # windows path => convert slashes
            return Path(PureWindowsPath(decoded_path).as_posix())
        return Path(decoded_path)


class DeafBeadHandler(StructHandler):
    NAME = "deafbead"
    PATTERNS = [HexString("DE AF BE AD (86 | 87)")]

    DOC = HandlerDoc(
        name="D-Link DEAFBEAD",
        description="Archive files as found in D-Link DSL-500G and DSL-504G firmware images.",
        handler_type=HandlerType.ARCHIVE,
        vendor="D-Link",
        references=[],
        limitations=[],
    )

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "deafbead_header_t"
    EXTRACTOR = DeafBeadExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        file.seek(start_offset + HEADER_LEN)
        while (magic := file.read(1)) in VALID_MAGICS:
            file.seek(-1, io.SEEK_CUR)
            if magic == DIR_MAGIC:
                header = self.cparser_le.deafbead_dir_t(file)
                if header.name_len == 0:
                    raise InvalidInputFormat("Invalid directory header.")
            else:
                header = self.cparser_le.deafbead_file_t(file)
                if header.name_len == 0 or header.file_size == 0:
                    raise InvalidInputFormat("Invalid file header.")

        end_offset = file.tell()
        if magic:  # if EOF wasn't reached (i.e. magic is not empty), we need to undo the last read
            end_offset -= 1
        return ValidChunk(start_offset=start_offset, end_offset=end_offset)
