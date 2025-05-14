import hashlib
import io
from pathlib import Path
from typing import Optional

from unblob.file_utils import Endian, StructParser
from unblob.models import (
    DirectoryHandler,
    Glob,
    MultiFile,
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

    def is_valid_header(self, file_paths: list) -> bool:
        for path in file_paths:
            with path.open("rb") as f:
                header = HEADER_PARSER.parse(HEADER_STRUCT, f, Endian.LITTLE)
                if header.magic != PAR2_MAGIC:
                    return False

                offset_to_recovery_id = 32
                # seek to beginning of recovery set ID
                f.seek(offset_to_recovery_id, io.SEEK_SET)
                packet_content = f.read(
                    header.packet_length - len(header) + offset_to_recovery_id
                )
                packet_checksum = hashlib.md5(packet_content).digest()  # noqa: S324

                if packet_checksum != header.md5_hash:
                    return False
        return True

    def calculate_multifile(self, file: Path) -> Optional[MultiFile]:
        paths = sorted(
            [p for p in file.parent.glob(f"{file.stem}.*") if p.resolve().exists()]
        )

        if len(paths) <= 1 or not self.is_valid_header(paths):
            return None

        return MultiFile(
            name=file.stem,
            paths=paths,
        )
