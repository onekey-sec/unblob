import io
import struct
import zipfile

import pytest

from unblob.file_utils import File, InvalidInputFormat
from unblob.handlers.archive.zip import ZIPHandler

EOCD_SIGNATURE = b"PK\x05\x06"
CD_FILE_HEADER_SIZE = 46
CD_FLAGS_OFFSET = 8

handler = ZIPHandler()


def build_zip(comment: bytes, entries: int = 3) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for index in range(entries):
            info = zipfile.ZipInfo(f"file{index}.txt")
            info.comment = comment
            archive.writestr(info, b"content %d\n" % index)
    return buffer.getvalue()


def central_directory_offset(content: bytes) -> int:
    eocd_offset = content.rfind(EOCD_SIGNATURE)
    (offset_of_cd,) = struct.unpack_from("<I", content, eocd_offset + 16)
    return offset_of_cd


def set_entry_flags(content: bytes, entry_offset: int, flags: int) -> bytes:
    patched = bytearray(content)
    struct.pack_into("<H", patched, entry_offset + CD_FLAGS_OFFSET, flags)
    return bytes(patched)


@pytest.mark.parametrize(
    "comment",
    [
        pytest.param(b"", id="no-comment"),
        pytest.param(b"a file comment", id="text-comment"),
        # the comment bytes land where the next header's flags would be read
        pytest.param(b"\x00" * 8 + b"\x01\x00" + b"\x00" * 20, id="flags-in-comment"),
        # long enough to push a mis-parsed walk past the end of the file
        pytest.param(b"\xff" * 64, id="long-comment"),
    ],
)
def test_entry_comments_do_not_mark_archive_encrypted(comment: bytes):
    content = build_zip(comment)
    chunk = handler.calculate_chunk(File.from_bytes(content), 0)

    assert chunk is not None
    assert chunk.start_offset == 0
    assert chunk.end_offset == len(content)
    assert not chunk.is_encrypted


def test_encrypted_entry_after_commented_entry_is_detected():
    content = build_zip(b"a file comment", entries=2)
    first_entry = central_directory_offset(content)
    second_entry = (
        first_entry + CD_FILE_HEADER_SIZE + len("file0.txt") + len(b"a file comment")
    )
    content = set_entry_flags(content, second_entry, handler.ENCRYPTED_FLAG)

    chunk = handler.calculate_chunk(File.from_bytes(content), 0)

    assert chunk is not None
    assert chunk.is_encrypted


def test_invalid_central_directory_header_is_rejected():
    content = build_zip(b"", entries=1)
    cd_offset = central_directory_offset(content)
    content = content[:cd_offset] + b"PK\x07\x08" + content[cd_offset + 4 :]

    with pytest.raises(InvalidInputFormat, match="central directory"):
        handler.calculate_chunk(File.from_bytes(content), 0)
