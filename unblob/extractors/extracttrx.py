import io
import os
import shutil
import stat
import struct
from enum import IntEnum, unique
from pathlib import Path
from typing import Dict, Optional

import click
from structlog import get_logger

from ..file_utils import round_up
from ..logging import configure_logger

logger = get_logger()

HEADER_LEN = 28


class TRXHeader(object):
    def __init__(
        self,
        file: io.BufferedReader,
        extract_root: Path,
        force_overwrite: bool = False,
    ):

        self.file = file
        self.file.seek(0, io.SEEK_END)
        self.eof = self.file.tell()
        self.file.seek(0, io.SEEK_SET)

        # if self.eof < ROMFS_HEADER_SIZE:
        #     raise Exception("File too small to hold ROMFS")

        self.magic = self.file.read(4)
        self.len = struct.unpack("<I", self.file.read(4))[0]
        self.file.read(4) # CRC
        self.file.read(4)  # FLAG & VERSION
        self.offset0 = struct.unpack("<I", self.file.read(4))[0]
        self.offset1 = struct.unpack("<I", self.file.read(4))[0]
        self.offset2 = struct.unpack("<I", self.file.read(4))[0]

        extract_root.mkdir()

        self.extract_root = extract_root
        self.force_overwrite = force_overwrite

    def dump(self):
        print(f"{self.len} {self.offset0} {self.offset1} {self.offset2}")

        if self.offset0:
            self._dump_file('part0', self.offset0, self.offset1)
        if self.offset1:
            self._dump_file('part1', self.offset1, self.offset2)
        if self.offset2:
            self._dump_file('part2', self.offset2, 0)


    def _dump_file(self, filename, start, end):
        output_path = self.extract_root.joinpath(filename).resolve()
        with output_path.open("wb") as f:
            if end < HEADER_LEN:
                end = self.eof
            self.file.seek(start)
            file_content = self.file.read(end - start)
            f.write(file_content)


@click.command(help="A tool to unpack TRX image.")
@click.argument(
    "trx_file",
    type=click.Path(path_type=Path, dir_okay=False, file_okay=True, exists=True),
)
@click.option(
    "-e",
    "--extract-dir",
    "extract_root",
    type=click.Path(path_type=Path, dir_okay=True, file_okay=False, resolve_path=True),
    default=Path.cwd(),
    help="Extract the files to this directory. Will be created if it doesn't exist.",
)
@click.option("-f", "--force", is_flag=True, help="Force overwrite.")
@click.option("-v", "--verbose", is_flag=True, help="Verbose mode, enable debug logs.")
def cli(trx_file: Path, extract_root: Path, force: bool, verbose: bool):
    configure_logger(verbose, extract_root)
    if not trx_file:
        logger.error("No file provided")
        return
    logger.info("Start processing file", path=trx_file)

    if os.path.isdir(extract_root):
        if force:
            shutil.rmtree(extract_root)
        else:
            logger.warning(
                f"extraction root {extract_root} already exists. Use -f operator to force overwrite."
            )
            return

    with trx_file.open("rb") as f:
        header = TRXHeader(f, extract_root, force)
        header.dump()


if __name__ == "__main__":
    cli()
