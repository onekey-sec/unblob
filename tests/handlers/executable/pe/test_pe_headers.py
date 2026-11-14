import gzip
from pathlib import Path

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.finder import search_chunks
from unblob.handlers.compression.gzip import GZIPHandler
from unblob.handlers.executable.pe._headers import DataDirectory
from unblob.handlers.executable.pe.pe import PEHandler
from unblob.models import Task, TaskResult
from unblob.testing import (
    PE_END,
    PE_PREFIX,
    PE_SECTION_SIZE,
    PE_SECTION_TABLE_END,
    PE_SECTION_VA,
    PE_SIZE_OF_HEADERS,
    PE_STRUCTS,
    PE_SUFFIX,
    build_pe,
    calculate_chunk,
    find_chunks,
    get_pe_image_end,
)

# Plain PE files


@pytest.mark.parametrize("plus", [False, True], ids=["pe32", "pe32+"])
def test_plain_pe_is_not_claimed(plus: bool):
    pe = build_pe(plus=plus)
    assert get_pe_image_end(pe) == PE_END

    assert calculate_chunk(PEHandler, pe) is None
    assert find_chunks(PEHandler, PE_PREFIX + pe + PE_SUFFIX) == []


def test_plain_pe_contents_are_searched():
    # e.g. a firmware image in the resources of an updater: the PE must not hide it
    data = gzip.compress(b"firmware image " * 64)
    data_offset = PE_SIZE_OF_HEADERS + 0x40
    pe = build_pe(section_size=0x400, section_data=b"\x00" * 0x40 + data)

    task_result = TaskResult(task=Task(path=Path("/nonexistent"), depth=0, blob_id=""))
    with File.from_bytes(pe) as file:
        chunks = search_chunks(file, len(pe), (PEHandler, GZIPHandler), task_result)

    assert task_result.reports == []
    assert [
        (chunk.handler.NAME, chunk.start_offset, chunk.end_offset) for chunk in chunks
    ] == [("gzip", data_offset, data_offset + len(data))]


def test_pe_at_end_of_file_not_aligned():
    # the NSIS probe at the next 512 byte boundary lies past the end of the file
    pe = build_pe(section_size=PE_SECTION_SIZE - 0x10)
    assert calculate_chunk(PEHandler, pe) is None
    assert find_chunks(PEHandler, pe) == []


# Image size, which locates appended payloads


def test_size_of_headers_without_section_data():
    # a section without raw data does not count, whatever its pointer
    pe = build_pe(section={"size_of_raw_data": 0, "pointer_to_raw_data": 0x10000})
    assert get_pe_image_end(pe + PE_SUFFIX) == PE_SIZE_OF_HEADERS


def test_section_table_beyond_size_of_headers():
    pe = build_pe(
        section={"size_of_raw_data": 0},
        optional_header={"size_of_headers": 0x100},
    )
    assert PE_SECTION_TABLE_END > 0x100
    assert get_pe_image_end(pe) == PE_SECTION_TABLE_END


def test_data_directories_beyond_16_are_ignored():
    # the loader only reads IMAGE_NUMBEROF_DIRECTORY_ENTRIES directories, a larger
    # count must neither be walked nor require a larger optional header
    pe = build_pe(optional_header={"number_of_rva_and_sizes": 0xFFFFFFFF})
    assert get_pe_image_end(pe + PE_SUFFIX) == PE_END


def test_few_data_directories():
    # neither the debug nor the certificate table directory is present
    pe = build_pe(optional_header={"number_of_rva_and_sizes": 2})
    assert get_pe_image_end(pe + PE_SUFFIX) == PE_END


def test_debug_data_outside_sections_is_included():
    debug_size = 0x2C
    # the second entry has no file data: its size must not count
    pe = build_pe(debug_entries=[(PE_END, debug_size), (0, 0x10000)])
    assert (
        get_pe_image_end(pe + b"\xdd" * debug_size + PE_SUFFIX) == PE_END + debug_size
    )


@pytest.mark.parametrize(
    "debug_directory, section",
    [
        pytest.param((0x8000, 0x1C), {}, id="outside-sections"),
        pytest.param(
            (PE_SECTION_VA + PE_SECTION_SIZE, 0x1C),
            {"virtual_size": 0x1000},
            id="zero-filled-section-tail",
        ),
        pytest.param(
            (PE_SECTION_VA + PE_SECTION_SIZE - 0x10, 0x1C), {}, id="crosses-section-end"
        ),
    ],
)
def test_unmapped_debug_directory_is_ignored(debug_directory, section):
    pe = build_pe(
        data_directories={DataDirectory.DEBUG: debug_directory}, section=section
    )
    # data the debug directory would be read from, pointing far beyond the file
    trailer = PE_STRUCTS.debug_directory_t(
        size_of_data=0x10000, pointer_to_raw_data=1
    ).dumps()
    assert get_pe_image_end(pe + trailer) == PE_END


def test_debug_directory_in_section_without_file_data_is_ignored():
    # a section without file data (pointer_to_raw_data == 0) maps nothing: the
    # directory must not be read from offset 0 + its offset in the section
    directory_offset = 0x180
    pe = bytearray(
        build_pe(
            section={"pointer_to_raw_data": 0},
            data_directories={
                DataDirectory.DEBUG: (PE_SECTION_VA + directory_offset, 0x1C)
            },
        )
    )
    assert directory_offset >= PE_SECTION_TABLE_END
    entry = PE_STRUCTS.debug_directory_t(
        size_of_data=0x10000, pointer_to_raw_data=1
    ).dumps()
    pe[directory_offset : directory_offset + len(entry)] = entry

    # the headers end where the section's (bogus) raw data at offset 0 ends
    assert get_pe_image_end(bytes(pe)) == PE_SIZE_OF_HEADERS == PE_SECTION_SIZE


def test_debug_directory_before_section_is_ignored():
    # an RVA below the section start would map into the headers
    directory_offset = 0x180
    rva = PE_SECTION_VA - (PE_SIZE_OF_HEADERS - directory_offset)
    pe = bytearray(build_pe(data_directories={DataDirectory.DEBUG: (rva, 0x1C)}))
    assert directory_offset >= PE_SECTION_TABLE_END
    entry = PE_STRUCTS.debug_directory_t(
        size_of_data=0x10000, pointer_to_raw_data=1
    ).dumps()
    pe[directory_offset : directory_offset + len(entry)] = entry

    assert get_pe_image_end(bytes(pe)) == PE_END


def test_coff_symbol_table_is_included():
    number_of_symbols = 2
    strings = b"long_symbol_name\x00"
    pe = build_pe(
        file_header={
            "pointer_to_symbol_table": PE_END,
            "number_of_symbols": number_of_symbols,
        }
    )
    string_table = (4 + len(strings)).to_bytes(4, "little") + strings
    symbols = b"\x55" * (18 * number_of_symbols) + string_table
    assert get_pe_image_end(pe + symbols + PE_SUFFIX) == PE_END + len(symbols)


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"file_header": {"signature": b"PE\x00\x01"}}, id="signature"),
        pytest.param({"file_header": {"number_of_sections": 0}}, id="no-sections"),
        pytest.param({"optional_header": {"magic": 0x107}}, id="optional-header-magic"),
        pytest.param(
            {"file_header": {"size_of_optional_header": 96 + 16 * 8 - 1}},
            id="optional-header-too-small",
        ),
        pytest.param(
            {"debug_entries": [(PE_END, 1)] * 65}, id="too-many-debug-entries"
        ),
        pytest.param(
            {
                "file_header": {
                    "pointer_to_symbol_table": PE_SIZE_OF_HEADERS,
                    "number_of_symbols": 1,
                },
                # the string table length after the single symbol is 0
            },
            id="string-table-length",
        ),
    ],
)
def test_invalid_headers(kwargs: dict):
    # the headers are validated before looking for a payload
    pe = build_pe(**kwargs)
    with pytest.raises(InvalidInputFormat):
        calculate_chunk(PEHandler, pe)
