import subprocess
import sys
from distutils.dist import Distribution
from functools import partial
from pathlib import Path

from setuptools import Extension
from setuptools.command.build_ext import build_ext as SetupToolsBuildExt


class ZigCompilerError(Exception):
    """Some compile/link operation failed."""


# From: https://sourceforge.net/p/setuptools-zig/code/ci/default/tree/setuptools_zig.py#l29
class ZigBuildExt(SetupToolsBuildExt):
    def __init__(self, dist: Distribution, zig_value):
        self._zig_value = zig_value
        super().__init__(dist)

    def build_extension(self, ext: Extension):
        if not self._zig_value:
            return super().build_extension(ext)

        # check if every file in ext.sources exists
        for p in ext.sources:
            assert Path(p).exists()

        distout = Path(self.get_ext_filename(ext.name))
        target = Path(self.get_ext_fullpath(ext.name))
        print("DISTOUT:", distout)
        print("TARGET:", target)

        build_cmd = self._make_zig_build_cmd(ext, distout.stem)

        subprocess.run(build_cmd)
        output = self._get_output(distout)
        self._move_output(output, target)

    def _make_zig_build_cmd(self, ext: Extension, name: str):
        build_cmd = [
            "python",
            "-m",
            "ziglang",
            "build-lib",
            "-dynamic",
            "-DPYHEXVER={}".format(sys.hexversion),
            "--name",
            name,
        ]
        for inc_dir in self.compiler.include_dirs:
            build_cmd.extend(("-I", inc_dir))
        build_cmd.extend(("-I", "/usr/include"))
        build_cmd.extend(ext.sources)
        print(f"cmd: {build_cmd}")
        return build_cmd

    def _get_output(self, output: Path):
        # zig prefixes the compiled file with "lib"
        output = output.parent / ("lib" + output.name)
        if not output.exists():
            raise ZigCompilerError(f"compilation failed: {output} does not exist")
        return output

    def _move_output(self, output: Path, target: Path):
        if target.exists():
            target.unlink()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)

        output.rename(target)


def setup_build_zig(dist: Distribution, keyword: str, value):
    assert isinstance(dist, Distribution)
    assert keyword == "build_zig"
    dist.cmdclass["build_ext"] = partial(ZigBuildExt, zig_value=value)


def build(setup_kwargs):
    setup_kwargs.update(
        {
            "entry_points": {
                "distutils.setup_keywords": ["build_zig=build:setup_build_zig"]
            },
            "build_zig": True,
            "ext_modules": [
                Extension("zigmath", ["zig/math.zig"]),
            ],
        }
    )
