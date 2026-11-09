"""Regenerate integration fixtures using Apache NuttX's image generator.

Run from the repository root with Python 3.10+ and a C compiler. Downloads the
pinned Apache-2.0 source over HTTPS; no NuttX SDK or runtime is needed.
"""

import random
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

NUTTX_COMMIT = "6bdd71565ad4d0095b73f09ab81c4f570b2aeec5"
SOURCE_URL = (
    f"https://raw.githubusercontent.com/apache/nuttx/{NUTTX_COMMIT}/tools/gencromfs.c"
)
DESTINATION = Path(__file__).resolve().parents[3] / "integration/filesystem/cromfs"


def generate():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        source = root / "gencromfs.c"
        with urllib.request.urlopen(SOURCE_URL) as response:
            source.write_bytes(response.read())
        files = root / "files"
        files.mkdir()
        (files / "nested").mkdir()
        (files / "empty-dir").mkdir()
        (files / "nested/message.txt").write_bytes(b"Hello from NuttX CROMFS!\n" * 60)
        (files / "raw.bin").write_bytes(random.Random(0).randbytes(1024))  # noqa: S311 (reproducible fixture)
        (files / "empty.txt").touch()
        (files / "caf\u00e9.txt").write_bytes(b"Unicode filename\n")
        for endian in ("little", "big"):
            executable = root / f"gencromfs-{endian}"
            flags = ["-DHOST_BIGENDIAN"] if sys.byteorder == "big" else []
            if endian == "big":
                flags.append("-DTGT_BIGENDIAN")
            subprocess.run(
                ["cc", "-O2", *flags, str(source), "-o", str(executable)], check=True
            )
            generated = root / "image.c"
            subprocess.run([str(executable), str(files), str(generated)], check=True)
            text = re.sub(r"/\*.*?\*/", "", generated.read_text(), flags=re.DOTALL)
            data = bytes(
                int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", text)
            )
            destination = DESTINATION / endian
            inputs = destination / "__input__"
            inputs.mkdir(parents=True, exist_ok=True)
            for name, image in (
                ("sample.cromfs", data),
                ("sample.padded.cromfs", b"\0" * 16 + data + b"\0" * 16),
            ):
                (inputs / name).write_bytes(image)
                output = destination / "__output__" / f"{name}_extract"
                output.mkdir(parents=True, exist_ok=True)
                if name == "sample.padded.cromfs":
                    (output / "0-16.padding").write_bytes(b"\0" * 16)
                    (output / f"{len(data) + 16}-{len(data) + 32}.padding").write_bytes(
                        b"\0" * 16
                    )
                    (output / f"16-{len(data) + 16}.cromfs").write_bytes(data)
                    output /= f"16-{len(data) + 16}.cromfs_extract"
                shutil.copytree(files, output, dirs_exist_ok=True)
                (output / "empty-dir/.gitkeep").touch()


if __name__ == "__main__":
    generate()
