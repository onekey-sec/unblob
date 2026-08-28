import hashlib
from pathlib import Path

from unblob.file_utils import Endian, StructParser, iterate_file
from unblob.models import (
    DirectoryHandler,
    Glob,
    HandlerDoc,
    HandlerType,
    MultiFile,
    Reference,
)

C_DEFINITIONS = r"""
    typedef struct par2_header{
        char magic[8];
        uint64 packet_length;
        char md5_hash[16];
        char recovery_set_id[16];
        char type[16];
    } par2_header_t;
"""

PAR2_MAGIC = b"PAR2\x00PKT"
HEADER_STRUCT = "par2_header_t"
HEADER_PARSER = StructParser(C_DEFINITIONS)


class MultiVolumePAR2Handler(DirectoryHandler):
    NAME = "multi-par2"
    PATTERN = Glob("*.par2")
    EXTRACTOR = None

    DOC = HandlerDoc(
        name="PAR2 (multi-volume)",
        description="Parchive or PAR2, is a format for creating redundant data that helps detect and repair corrupted files. These archives typically accompany split-file sets (like multi-volume RAR or ZIP archives). Each PAR2 file is composed of multiple 'packets'.",
        handler_type=HandlerType.ARCHIVE,
        vendor=None,
        references=[
            Reference(
                title="Parchive Documentation",
                url="https://parchive.github.io/",
            ),
        ],
        limitations=[],
    )

    def is_valid_header(self, file_paths: list) -> bool:
        for path in file_paths:
            with path.open("rb") as f:
                header = HEADER_PARSER.parse(HEADER_STRUCT, f, Endian.LITTLE)
                if header.magic != PAR2_MAGIC:
                    return False

                offset_to_recovery_id = 32
                packet_checksum_state = hashlib.md5(usedforsecurity=False)
                packet_content_length = (
                    header.packet_length - len(header) + offset_to_recovery_id
                )
                for chunk in iterate_file(
                    f, offset_to_recovery_id, packet_content_length
                ):
                    packet_checksum_state.update(chunk)

                packet_checksum = packet_checksum_state.digest()

                if packet_checksum != header.md5_hash:
                    return False
        return True

    def calculate_multifile(self, file: Path) -> MultiFile | None:
        paths = sorted(
            [p for p in file.parent.glob(f"{file.stem}.*") if p.resolve().exists()]
        )

        if len(paths) <= 1 or not self.is_valid_header(paths):
            return None

        return MultiFile(
            name=file.stem,
            paths=paths,
        )
