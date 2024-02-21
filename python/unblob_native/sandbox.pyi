import os
import typing

import typing_extensions

_Path: typing_extensions.TypeAlias = typing.Union[os.PathLike, str]

class AccessFS:
    @staticmethod
    def read(access_dir: _Path) -> AccessFS: ...
    @staticmethod
    def read_write(access_dir: _Path) -> AccessFS: ...
    @staticmethod
    def make_reg(access_dir: _Path) -> AccessFS: ...
    @staticmethod
    def make_dir(access_dir: _Path) -> AccessFS: ...

def restrict_access(*args: AccessFS) -> None: ...

class SandboxError(Exception): ...
