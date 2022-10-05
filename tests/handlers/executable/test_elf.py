from pathlib import Path
from unittest.mock import ANY

import pytest
from helpers import unhex

from unblob.file_utils import File
from unblob.handlers.executable.elf import ELF64Handler
from unblob.models import ValidChunk
from unblob.processing import ExtractionConfig, Task, process_file
from unblob.report import ChunkReport

ELF_CONTENT = unhex(
    """\
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 3e 00 01 00 00 00  60 10 00 00 00 00 00 00  |..>.....`.......|
00000020  40 00 00 00 00 00 00 00  30 10 00 00 00 00 00 00  |@.......0.......|
00000030  00 00 00 00 40 00 38 00  0c 00 40 00 03 00 02 00  |....@.8...@.....|
00000040  06 00 00 00 04 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000050  40 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |@.......@.......|
00000060  a0 02 00 00 00 00 00 00  a0 02 00 00 00 00 00 00  |................|
00000070  08 00 00 00 00 00 00 00  03 00 00 00 04 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00  18 03 00 00 00 00 00 00  |................|
00000090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000a0  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
000000b0  01 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000d0  e0 02 00 00 00 00 00 00  e0 02 00 00 00 00 00 00  |................|
000000e0  00 10 00 00 00 00 00 00  01 00 00 00 05 00 00 00  |................|
000000f0  00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00000100  00 10 00 00 00 00 00 00  1b 00 00 00 00 00 00 00  |................|
00000110  1b 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00000120  01 00 00 00 04 00 00 00  e0 02 00 00 00 00 00 00  |................|
00000130  00 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |. ..............|
00000140  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000150  00 10 00 00 00 00 00 00  01 00 00 00 06 00 00 00  |................|
00000160  e0 02 00 00 00 00 00 00  b8 3d 00 00 00 00 00 00  |.........=......|
00000170  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000180  00 00 00 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00000190  02 00 00 00 06 00 00 00  00 00 00 00 00 00 00 00  |................|
000001a0  c8 3d 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |.=..............|
000001b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001c0  08 00 00 00 00 00 00 00  04 00 00 00 04 00 00 00  |................|
000001d0  00 00 00 00 00 00 00 00  38 03 00 00 00 00 00 00  |........8.......|
000001e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001f0  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
00000200  04 00 00 00 04 00 00 00  00 00 00 00 00 00 00 00  |................|
00000210  68 03 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |h...............|
00000220  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000230  08 00 00 00 00 00 00 00  53 e5 74 64 04 00 00 00  |........S.td....|
00000240  00 00 00 00 00 00 00 00  38 03 00 00 00 00 00 00  |........8.......|
00000250  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000260  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
00000270  50 e5 74 64 04 00 00 00  00 00 00 00 00 00 00 00  |P.td............|
00000280  0c 20 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |. ..............|
00000290  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000002a0  08 00 00 00 00 00 00 00  51 e5 74 64 06 00 00 00  |........Q.td....|
000002b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
000002d0  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
000002e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001000  f3 0f 1e fa 48 83 ec 08  48 8b 05 d9 2f 00 00 48  |....H...H.../..H|
00001010  85 c0 74 02 ff d0 48 83  c4 08 c3 00 2e 73 68 73  |..t...H......shs|
00001020  74 72 74 61 62 00 2e 69  6e 69 74 00 00 00 00 00  |trtab..init.....|
00001030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
00001070  0b 00 00 00 01 00 00 00  06 00 00 00 00 00 00 00  |................|
00001080  00 10 00 00 00 00 00 00  00 10 00 00 00 00 00 00  |................|
00001090  1b 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000010a0  04 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000010b0  01 00 00 00 03 00 00 00  00 00 00 00 00 00 00 00  |................|
000010c0  00 00 00 00 00 00 00 00  1b 10 00 00 00 00 00 00  |................|
000010d0  11 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000010e0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000010f0
"""
)


def test_chunk_is_calculated():
    file = File.from_bytes(ELF_CONTENT)
    chunk = ELF64Handler().calculate_chunk(file, 0)

    assert isinstance(chunk, ValidChunk)
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(ELF_CONTENT)


@pytest.mark.parametrize(
    "offset, byte",
    [
        pytest.param(0x10, 0xFE, id="invalid e_type"),
        pytest.param(0x12, 0xFE, id="invalid e_machine"),
        pytest.param(0x14, 0xFE, id="invalid e_version"),
    ],
)
def test_invalid_header(offset, byte):
    file = File.from_bytes(ELF_CONTENT)
    file[offset] = byte
    chunk = ELF64Handler().calculate_chunk(file, 0)

    assert chunk is None


def test_carved_out_elf_files_are_processed_again(
    tmp_path: Path, extraction_config: ExtractionConfig
):
    """Processing carved out ELF files is special: we want to keep the ELF file around,
    and also present in the output report as a separate task entity with its reports.

    This is achieved by running the ELF handler twice, once on the carved out chunk,
    next again on the same physical file, but within the scope of a separate `Task`.
    """
    PREFIX = b"-some-prefix"
    SUFFIX = b"suffix-"
    input_path = tmp_path / "input_path"
    input_path.write_bytes(PREFIX + ELF_CONTENT + SUFFIX)

    extraction_config.keep_extracted_chunks = False
    reports = process_file(extraction_config, input_path)

    # we should still have the carved ELF file, even if deleting extracted chunks was requested
    carved_elf_path = (
        extraction_config.extract_root
        / f"{input_path.name}_extract/{len(PREFIX)}-{len(PREFIX) + len(ELF_CONTENT)}.elf64"
    )
    assert carved_elf_path.read_bytes() == ELF_CONTENT

    # we expect results for 2 connected tasks
    [carve_elf, handle_elf] = reports.results

    # first pass: carve elf file from input_path, but postpone its real processing to a new task
    [chunk_report] = [r for r in carve_elf.reports if isinstance(r, ChunkReport)]
    [subtask] = carve_elf.subtasks
    assert chunk_report == ChunkReport(
        id=subtask.chunk_id,
        handler_name="elf64",
        start_offset=len(PREFIX),
        end_offset=len(PREFIX) + len(ELF_CONTENT),
        size=len(ELF_CONTENT),
        is_encrypted=False,
        extraction_reports=[],
    )

    # second pass: process carved out elf file
    assert handle_elf.task == Task(
        path=carved_elf_path, depth=1, chunk_id=subtask.chunk_id
    )
    [chunk_report] = [r for r in handle_elf.reports if isinstance(r, ChunkReport)]
    assert chunk_report == ChunkReport(
        id=ANY,
        handler_name="elf64",
        start_offset=0,
        end_offset=len(ELF_CONTENT),
        size=len(ELF_CONTENT),
        is_encrypted=False,
        extraction_reports=[],
    )
