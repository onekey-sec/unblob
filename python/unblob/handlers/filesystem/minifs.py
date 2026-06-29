from __future__ import annotations

import io
import lzma
from dataclasses import dataclass
from pathlib import Path

from unblob.file_utils import Endian, File, FileSystem, InvalidInputFormat, StructParser
from unblob.models import (
    Extractor,
    ExtractResult,
    Handler,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    ValidChunk,
)

# the structure of the FS is as follows (as described in https://arxiv.org/html/2407.05064v1):
# - header (32 bytes)
# - table with the file paths/names
# - table with other file info (size, offsets in the other tables)
# - table of chunks
# - chunk data (LZMA FORMAT_ALONE compressed; chunks can contain one or multiple files)
C_DEFINITIONS = r"""
    typedef struct minifs_header {
        char magic[6];              /* "MINIFS" */
        char unknown0[10];          /* empty / padding */
        uint32 unknown1;            /* always 0x3 in the samples; maybe version? */
        uint32 file_count;          /* number of files in the FS */
        uint32 first_chunk_len;     /* size of the first chunk (unclear why this needs to be in the header) */
        uint32 name_table_len;      /* size of the file name table */
    } minifs_header_t;

    typedef struct file_table_entry {
        uint32 path_offset;
        uint32 name_offset;
        uint32 chunk_id;
        uint32 chunk_offset;
        uint32 file_len;
    } file_table_entry_t;

    typedef struct chunk_table_entry {
        uint32 data_offset;
        uint32 compressed_size;
        uint32 decompressed_size;
    } chunk_table_entry_t;
"""
MAX_FILE_COUNT = 0x10_000  # sanity check; a higher number is unrealistic
MAX_PATH_LEN = 1024  # sanity check; actual limits of this FS are unknown but the longest oberved path was 53 chars
LZMA_MEM_LIMIT = 2**20 * 48  # 48 MiB


@dataclass
class MiniFSFile:
    path: Path
    chunk_id: int
    chunk_offset: int  # relative offset of the file in the decompressed chunk
    length: int

    @classmethod
    def from_file_table_entry(cls, entry, names_data: bytes) -> MiniFSFile:
        return cls(
            path=cls._resolve_path(names_data, entry),
            chunk_id=entry.chunk_id,
            chunk_offset=entry.chunk_offset,
            length=entry.file_len,
        )

    @classmethod
    def _resolve_path(cls, names_data: bytes, entry) -> Path:
        path = cls._extract_cstring_at(names_data, entry.path_offset)
        name = cls._extract_cstring_at(names_data, entry.name_offset)
        return Path(f"{path}/{name}")

    @staticmethod
    def _extract_cstring_at(names_data: bytes, offset: int) -> str:
        end = names_data.index(b"\x00", offset)
        if end == -1:
            raise InvalidInputFormat("Expected string, but reached EoF.")
        return names_data[offset:end].decode("utf-8", errors="surrogateescape")


@dataclass
class MiniFSChunk:
    data_offset: int
    compressed_size: int
    decompressed_size: int
    id: int

    @classmethod
    def from_chunk_table_entry(cls, entry, chunk_id: int) -> MiniFSChunk:
        return cls(
            data_offset=entry.data_offset,
            compressed_size=entry.compressed_size,
            decompressed_size=entry.decompressed_size,
            id=chunk_id,
        )


class MiniFSParser:
    def __init__(self, file: File):
        self._struct_parser = StructParser(C_DEFINITIONS)
        self._files_by_chunk = None

        self._start_offset = file.tell()
        self.header = self._struct_parser.parse("minifs_header_t", file, Endian.BIG)
        self._validate_header(file)

        names_data = file.read(self.header.name_table_len)
        self.file_entries = [
            MiniFSFile.from_file_table_entry(
                self._struct_parser.parse("file_table_entry_t", file, Endian.BIG),
                names_data,
            )
            for _ in range(self.header.file_count)
        ]

        self.chunk_entries = [
            MiniFSChunk.from_chunk_table_entry(
                self._struct_parser.parse("chunk_table_entry_t", file, Endian.BIG),
                chunk_id,
            )
            for chunk_id in range(self._get_chunk_count())
        ]
        self.chunk_data_offset = file.tell()

    def _get_chunk_count(self) -> int:
        return max(f.chunk_id for f in self.file_entries) + 1

    @property
    def files_by_chunk(self) -> dict[int, list[MiniFSFile]]:
        if self._files_by_chunk is None:
            self._files_by_chunk = {}
            for file in self.file_entries:
                self._files_by_chunk.setdefault(file.chunk_id, []).append(file)
            for file_list in self._files_by_chunk.values():
                file_list.sort(key=lambda file: file.chunk_offset)
        return self._files_by_chunk

    def _validate_header(self, file: File) -> None:
        if self.header.file_count == 0 or self.header.file_count > MAX_FILE_COUNT:
            raise InvalidInputFormat(
                f"Invalid number of files: {self.header.file_count}"
            )
        if self.header.first_chunk_len == 0:
            raise InvalidInputFormat("Invalid first chunk size: 0")
        if (
            self.header.name_table_len == 0
            or self.header.name_table_len > file.size() - self._start_offset
            or self.header.name_table_len > self.header.file_count * MAX_PATH_LEN
        ):
            raise InvalidInputFormat("Invalid file name table length.")


class MiniFSExtractor(Extractor):
    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(path=inpath) as input_file:
            parser = MiniFSParser(input_file)
            for chunk in parser.chunk_entries:
                decompressed = self._decompress_chunk(
                    input_file, parser.chunk_data_offset, chunk
                )
                for file in parser.files_by_chunk[chunk.id]:
                    fs.write_bytes(
                        file.path,
                        decompressed[
                            file.chunk_offset : file.chunk_offset + file.length
                        ],
                    )
        return ExtractResult(reports=fs.problems)

    @staticmethod
    def _decompress_chunk(
        file: File, chunk_data_start: int, chunk: MiniFSChunk
    ) -> bytes:
        file.seek(chunk_data_start + chunk.data_offset, io.SEEK_SET)
        raw = file.read(chunk.compressed_size)
        decompressor = lzma.LZMADecompressor(
            format=lzma.FORMAT_ALONE, memlimit=LZMA_MEM_LIMIT
        )
        try:
            return decompressor.decompress(raw, max_length=chunk.decompressed_size)
        except lzma.LZMAError as error:
            raise InvalidInputFormat("LZMA decompression failed.") from error


class MiniFSHandler(Handler):
    NAME = "minifs"
    PATTERNS = [
        HexString("4D 49 4E 49 46 53 00 00 00 00 00 00 00 00 00 00 00 00 00 03")
    ]

    DOC = HandlerDoc(
        name="MiniFS",
        description="Proprietary read-only filesystem used in TP-Link embedded firmware.",
        handler_type=HandlerType.FILESYSTEM,
        vendor="TP-Link",
        references=[
            Reference(
                title="Reverse Engineered MiniFS File System",
                url="https://arxiv.org/html/2407.05064v1",
            )
        ],
        limitations=[
            "There could be more versions of MiniFS which may not be unpacked successfully."
        ],
    )

    C_DEFINITIONS = C_DEFINITIONS
    HEADER_STRUCT = "minifs_header_t"
    EXTRACTOR = MiniFSExtractor()

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        parser = MiniFSParser(file)
        end_of_last_chunk = max(
            c.data_offset + c.compressed_size for c in parser.chunk_entries
        )
        return ValidChunk(
            start_offset=start_offset,
            end_offset=parser.chunk_data_offset + end_of_last_chunk,
        )
