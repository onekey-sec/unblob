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


class CHKHeader(object):
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
        self.header_len = struct.unpack(">I", self.file.read(4))[0]
        self.file.read(8) # Reserved
        self.kernel_checksum = struct.unpack(">I", self.file.read(4))[0]
        self.rootfs_checksum = struct.unpack(">I", self.file.read(4))[0]
        self.kernel_len = struct.unpack(">I", self.file.read(4))[0]
        self.rootfs_len = struct.unpack(">I", self.file.read(4))[0]

        extract_root.mkdir()

        self.extract_root = extract_root
        self.force_overwrite = force_overwrite

    def dump(self):
        self.file.seek(self.header_len)

        self._dump_file('kernel', self.kernel_len)
        self._dump_file('rootfs', self.rootfs_len)

    def _dump_file(self, filename, file_len):
        output_path = self.extract_root.joinpath(filename).resolve()
        with output_path.open("wb") as f:
            # check file_len
            file_content = self.file.read(file_len)
            f.write(file_content)


@click.command(help="A tool to unpack CHK image.")
@click.argument(
    "chk_file",
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
def cli(chk_file: Path, extract_root: Path, force: bool, verbose: bool):
    configure_logger(verbose, extract_root)
    if not chk_file:
        logger.error("No file provided")
        return
    logger.info("Start processing file", path=chk_file)

    if os.path.isdir(extract_root):
        if force:
            shutil.rmtree(extract_root)
        else:
            logger.warning(
                f"extraction root {extract_root} already exists. Use -f operator to force overwrite."
            )
            return

    with chk_file.open("rb") as f:
        header = CHKHeader(f, extract_root, force)
        header.dump()


if __name__ == "__main__":
    cli()
