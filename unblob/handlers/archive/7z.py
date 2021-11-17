from pathlib import Path
from typing import List


def make_extract_command(inpath: Path, outdir: Path) -> List[str]:
    assert outdir.is_dir(), "Output path must be a directory for 7zip!"
    infile = str(inpath.expanduser().resolve())
    out = str(outdir.expanduser().resolve())
    return ["7z", "x", "-y", infile, "-o", out]
