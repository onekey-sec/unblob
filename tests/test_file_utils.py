import io
import os
from pathlib import Path

import pytest

from unblob.file_utils import (
    Endian,
    File,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    chop_root,
    convert_int8,
    convert_int16,
    convert_int32,
    convert_int64,
    decode_multibyte_integer,
    get_endian,
    get_endian_short,
    is_safe_path,
    iterate_file,
    iterate_patterns,
    make_lost_and_found_path,
    round_down,
    round_up,
)
from unblob.report import LinkExtractionProblem, PathTraversalProblem


@pytest.mark.parametrize(
    "basedir, path, expected",
    [
        ("/lib/out", "/lib/out/file", True),
        ("/lib/out", "file", True),
        ("/lib/out", "dir/file", True),
        ("/lib/out", "some/dir/file", True),
        ("/lib/out", "some/dir/../file", True),
        ("/lib/out", "some/dir/../../file", True),
        ("/lib/out", "some/dir/../../../file", False),
        ("/lib/out", "some/dir/../../../", False),
        ("/lib/out", "some/dir/../../..", False),
        ("/lib/out", "../file", False),
        ("/lib/out", "/lib/out/../file", False),
    ],
)
def test_is_safe_path(basedir, path, expected):
    assert is_safe_path(Path(basedir), Path(path)) is expected


@pytest.mark.parametrize(
    "size, alignment, result",
    [
        (0, 5, 0),
        (1, 10, 0),
        (12, 10, 10),
        (29, 10, 20),
        (1, 512, 0),
    ],
)
def test_round_down(size, alignment, result):
    assert round_down(size, alignment) == result


@pytest.mark.parametrize(
    "size, alignment, result",
    [
        (0, 5, 0),
        (1, 10, 10),
        (12, 10, 20),
        (22, 10, 30),
        (1, 512, 512),
    ],
)
def test_round_up(size, alignment, result):
    assert round_up(size, alignment) == result


@pytest.fixture
def fake_file() -> File:
    return File.from_bytes(b"0123456789abcdefghijklmnopqrst")


class TestFile:
    def test_file_from_empty_bytes(self):
        with pytest.raises(ValueError):  # noqa: PT011
            File.from_bytes(b"")

    def test_file_from_empty_file(self, tmp_path):
        file_path = tmp_path / "file"
        file_path.touch()
        with pytest.raises(ValueError, match="cannot mmap an empty file"):
            File.from_path(file_path)


class TestStructParser:
    def test_parse_correct_endianness(self):
        test_content = b"\x01\x02\x03\x04"
        fake_file = File.from_bytes(test_content)

        definitions = r"""
        struct squashfs_header
        {
            uint32 inodes;
        }
        """
        parser = StructParser(definitions)

        header = parser.parse("squashfs_header", fake_file, Endian.BIG)
        assert header.inodes == 0x01_02_03_04

        fake_file = File.from_bytes(test_content)
        header2 = parser.parse("squashfs_header", fake_file, Endian.LITTLE)
        assert header2.inodes == 0x04_03_02_01


class TestConvertInt8:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00", Endian.LITTLE, 0x0),
            (b"\x00", Endian.BIG, 0x0),
            (b"\xff", Endian.LITTLE, 0xFF),
            (b"\xff", Endian.BIG, 0xFF),
            (b"\x10", Endian.LITTLE, 0x10),
            (b"\x10", Endian.BIG, 0x10),
        ],
    )
    def test_convert_int8(self, value: bytes, endian: Endian, expected: int):
        assert convert_int8(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int8(value, endian)


class TestConvertInt16:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff", Endian.LITTLE, 0xFFFF),
            (b"\xff\xff", Endian.BIG, 0xFFFF),
            (b"\x10\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00", Endian.BIG, 0x1000),
        ],
    )
    def test_convert_int16(self, value: bytes, endian: Endian, expected: int):
        assert convert_int16(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\xff", Endian.LITTLE),
            (b"\xff", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int16(value, endian)


class TestConvertInt32:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff", Endian.LITTLE, 0xFFFFFFFF),
            (b"\xff\xff\xff\xff", Endian.BIG, 0xFFFFFFFF),
            (b"\x10\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00", Endian.BIG, 0x10000000),
        ],
    )
    def test_convert_int32(self, value: bytes, endian: Endian, expected: int):
        assert convert_int32(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00", Endian.LITTLE),
            (b"\x00", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int32(value, endian)


class TestConvertInt64:
    @pytest.mark.parametrize(
        "value, endian, expected",
        [
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x0),
            (b"\x00\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x0),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.LITTLE, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff", Endian.BIG, 0xFFFF_FFFF_FFFF_FFFF),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.LITTLE, 0x10),
            (b"\x10\x00\x00\x00\x00\x00\x00\x00", Endian.BIG, 0x1000_0000_0000_0000),
        ],
    )
    def test_convert_int64(self, value: bytes, endian: Endian, expected: int):
        assert convert_int64(value, endian) == expected

    @pytest.mark.parametrize(
        "value, endian",
        [
            (b"", Endian.LITTLE),
            (b"", Endian.BIG),
            (b"\x00", Endian.LITTLE),
            (b"\x00", Endian.BIG),
            (b"\x00\x00", Endian.LITTLE),
            (b"\x00\x00", Endian.BIG),
            (b"\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff\xff", Endian.BIG),
            (b"\xff\xff\xff\xff\xff\xff\xff", Endian.LITTLE),
            (b"\xff\xff\xff\xff\xff\xff\xff", Endian.BIG),
        ],
    )
    def test_convert_invalid_values(self, value: bytes, endian: Endian):
        with pytest.raises(InvalidInputFormat):
            convert_int64(value, endian)


class TestMultibytesInteger:
    @pytest.mark.parametrize(
        "value, expected",
        [
            (b"\x00", (1, 0)),
            (b"\x01", (1, 1)),
            (b"\x01\x00", (1, 1)),
            (b"\x7f", (1, 127)),
            (b"\x7f\x00", (1, 127)),
            (b"\xff\x00", (2, 127)),
            (b"\x80\x08\x00", (2, 1024)),
            (b"\xff\xff\xff\xff\xff\xff\xff\x7f", (8, 0xFFFFFFFFFFFFFF)),
        ],
    )
    def test_decode_multibyte_integer(self, value: bytes, expected: int):
        assert decode_multibyte_integer(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            (b""),
            (b"\xff"),
            (b"\xff\xff\xff"),
        ],
    )
    def test_decode_invalid_values(self, value: bytes):
        with pytest.raises(InvalidInputFormat):
            decode_multibyte_integer(value)


@pytest.mark.parametrize(
    "content, pattern, expected",
    [
        (b"abcdef 123", b"abcdef", [0]),
        (b"abcdef abc", b"abcdef", [0]),
        (b"abcdef abcdef", b"abcdef", [0, 7]),
        (b"abcd", b"abcd", [0]),
        (b"abcdef abcdef", b"not-found", []),
    ],
)
def test_iterate_patterns(content: bytes, pattern: bytes, expected: list[int]):
    file = File.from_bytes(content)
    assert list(iterate_patterns(file, pattern)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size, expected",
    [
        pytest.param(b"0123456789", 0, 6, 3, [b"012", b"345"], id="from_start"),
        pytest.param(b"0123456789", 0, 0, 3, [], id="zero_size"),
        pytest.param(b"0123456789", 0, 5, 3, [b"012", b"34"], id="size_buffersize"),
        pytest.param(b"0123456789", 0, 5, 100, [b"01234"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 10, 10, [b"0123456789"], id="real_all"),
        pytest.param(b"0123456789", 0, 10, 100, [b"0123456789"], id="big_buffersize"),
        pytest.param(b"0123456789", 0, 100, 10, [b"0123456789"], id="big_size"),
        pytest.param(b"0123456789", 5, 3, 2, [b"56", b"7"], id="middle_offset"),
        pytest.param(b"0123456789", 10, 3, 2, [], id="offset_bigger_than_file"),
    ],
)
def test_iterate_file(
    content: bytes,
    start_offset: int,
    size: int,
    buffer_size: int,
    expected: list[bytes],
):
    file = File.from_bytes(content)
    assert list(iterate_file(file, start_offset, size, buffer_size)) == expected


@pytest.mark.parametrize(
    "content, start_offset, size, buffer_size",
    [
        pytest.param(b"012345", 0, 3, -1, id="negative_buffer_size"),
        pytest.param(b"012345", 0, 3, 0, id="zero_buffer_size"),
    ],
)
def test_iterate_file_errors(
    content: bytes, start_offset: int, size: int, buffer_size: int
):
    file = File.from_bytes(content)
    with pytest.raises(ValueError, match="buffer_size must be greater than 0"):
        list(iterate_file(file, start_offset, size, buffer_size))


class TestGetEndian:
    @pytest.mark.parametrize(
        "content, big_endian_magic, expected",
        [
            pytest.param(
                b"\xff\x00\x00\x10",
                0x100000FF,
                Endian.LITTLE,
                id="valid_little_endian",
            ),
            pytest.param(
                b"\x10\x00\x00\xff", 0x100000FF, Endian.BIG, id="valid_big_endian"
            ),
        ],
    )
    def test_get_endian(self, content: bytes, big_endian_magic: int, expected: Endian):
        file = File.from_bytes(content)
        assert get_endian(file, big_endian_magic) == expected

    @pytest.mark.parametrize(
        "content, big_endian_magic, expected",
        [
            pytest.param(b"\xff\x00", 0x00FF, Endian.LITTLE, id="valid_little_endian"),
            pytest.param(b"\x10\x00", 0x1000, Endian.BIG, id="valid_big_endian"),
        ],
    )
    def test_get_endian_short(
        self, content: bytes, big_endian_magic: int, expected: Endian
    ):
        file = File.from_bytes(content)
        assert get_endian_short(file, big_endian_magic) == expected

    @pytest.mark.parametrize(
        "content, big_endian_magic",
        [
            pytest.param(
                b"\x00\x00\x00\x01",
                0xFF_FF_FF_FF_FF,
                id="larger_than_32bit",
            ),
        ],
    )
    def test_get_endian_errors(self, content: bytes, big_endian_magic: int):
        file = File.from_bytes(content)
        with pytest.raises(
            ValueError, match="big_endian_magic is larger than a 32 bit integer"
        ):
            get_endian(file, big_endian_magic)

    @pytest.mark.parametrize(
        "content, big_endian_magic",
        [
            pytest.param(
                b"\x00\x00\x00\x01",
                0xFF_FF_FF,
                id="larger_than_16bit",
            ),
        ],
    )
    def test_get_endian_short_errors(self, content: bytes, big_endian_magic: int):
        file = File.from_bytes(content)
        with pytest.raises(
            ValueError, match="big_endian_magic is larger than a 16 bit integer"
        ):
            get_endian_short(file, big_endian_magic)

    def test_get_endian_resets_the_file_pointer(self):
        file = File.from_bytes(bytes.fromhex("FFFF 0000"))
        file.seek(-1, io.SEEK_END)
        pos = file.tell()
        with pytest.raises(InvalidInputFormat):
            get_endian(file, 0xFFFF_0000)
        assert file.tell() == pos

    def test_get_endian_short_resets_the_file_pointer(self):
        file = File.from_bytes(bytes.fromhex("FFFF"))
        file.seek(-1, io.SEEK_END)
        pos = file.tell()
        with pytest.raises(InvalidInputFormat):
            get_endian_short(file, 0xFFFF)
        assert file.tell() == pos


@pytest.mark.parametrize(
    "input_path, expected",
    [
        pytest.param("/", ".", id="absolute-root"),
        pytest.param("/path/to/file", "path/to/file", id="absolute-path"),
        pytest.param(".", ".", id="current-directory"),
        pytest.param("path/to/file", "path/to/file", id="relative-path"),
    ],
)
def test_chop_root(input_path: str, expected: str):
    assert chop_root(Path(input_path)) == Path(expected)


class TestFileSystem:
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/passwd",
            "file",
            "some/dir/file",
            "some/dir/../file",
            "some/dir/../../file",
        ],
    )
    def test_get_extraction_path_success(self, path):
        fs = FileSystem(Path("/unblob/sandbox"))
        extraction_path = fs._get_extraction_path(Path(path), "test")  # noqa: SLF001
        assert extraction_path
        assert os.path.commonpath([extraction_path.resolve(), fs.root]) == str(fs.root)

        assert fs.problems == []

    @pytest.mark.parametrize(
        "path",
        [
            "../file",
            "some/dir/../../../file",
            "some/dir/../../../",
            "some/dir/../../..",
        ],
    )
    def test_get_extraction_path_path_traversal_is_reported(self, path):
        fs = FileSystem(Path("/unblob/sandbox"))
        extraction_path = fs._get_extraction_path(Path(path), "test")  # noqa: SLF001
        assert extraction_path
        assert os.path.commonpath([extraction_path.resolve(), fs.root]) == str(fs.root)

        assert fs.problems

    def test_get_extraction_path_path_traversal_reports(self):
        fs = FileSystem(Path("/unblob/sandbox"))
        op1 = f"test1-{object()}"
        op2 = f"test2-{object()}"
        assert op1 != op2
        fs._get_extraction_path(Path("../file"), op1)  # noqa: SLF001
        fs._get_extraction_path(Path("../etc/passwd"), op2)  # noqa: SLF001

        report1, report2 = fs.problems

        assert isinstance(report1, PathTraversalProblem)
        assert "path traversal" in report1.problem
        assert op1 in report1.problem
        assert report1.path == "../file"

        assert isinstance(report2, PathTraversalProblem)
        assert "path traversal" in report2.problem
        assert op2 in report2.problem
        assert report2.path == "../etc/passwd"

    @pytest.fixture
    def sandbox_parent(self, tmp_path: Path):
        return tmp_path

    @pytest.fixture
    def sandbox_root(self, sandbox_parent: Path):
        return sandbox_parent / "sandbox"

    @pytest.fixture
    def sandbox(self, sandbox_root: Path):
        sandbox_root.mkdir(parents=True, exist_ok=True)
        return FileSystem(sandbox_root)

    def test_carve(self, sandbox: FileSystem):
        file = File.from_bytes(b"0123456789")
        sandbox.carve(Path("carved"), file, 1, 2)

        assert (sandbox.root / "carved").read_bytes() == b"12"
        assert sandbox.problems == []

    def test_carve_outside_sandbox(self, sandbox: FileSystem):
        file = File.from_bytes(b"0123456789")
        sandbox.carve(Path("../carved"), file, 1, 2)

        assert not (sandbox.root / "../carved").exists()
        assert sandbox.problems

    def test_mkdir(self, sandbox: FileSystem):
        sandbox.mkdir(Path("directory"))

        assert (sandbox.root / "directory").is_dir()
        assert sandbox.problems == []

    def test_mkdir_outside_sandbox(self, sandbox: FileSystem):
        try:
            sandbox.mkdir(Path("../directory"))
            pytest.fail(
                "expected failure, as lost+found directory is not created for mkdir"
            )
        except FileNotFoundError:
            pass

        sandbox.mkdir(Path("../directory"), parents=True)

        assert not (sandbox.root / "../directory").exists()
        assert sandbox.problems

    def test_mkfifo(self, sandbox: FileSystem):
        sandbox.mkfifo(Path("named_pipe"))

        assert (sandbox.root / "named_pipe").is_fifo()
        assert sandbox.problems == []

    def test_mkfifo_outside_sandbox(self, sandbox: FileSystem):
        sandbox.mkfifo(Path("../named_pipe"))

        assert not (sandbox.root / "../named_pipe").exists()
        assert sandbox.problems

    def test_create_symlink(self, sandbox: FileSystem):
        sandbox.create_symlink(Path("target file"), Path("symlink"))

        output_path = sandbox.root / "symlink"
        assert not output_path.exists()
        assert output_path.readlink() == Path("target file")
        assert sandbox.problems == []

    def test_create_symlink_target_inside_sandbox(self, sandbox: FileSystem):
        # ./sbin/shell -> ../bin/sh
        sandbox.mkdir(Path("bin"))
        sandbox.write_bytes(Path("bin/sh"), b"posix shell")
        sandbox.mkdir(Path("sbin"))
        sandbox.create_symlink(Path("../bin/sh"), Path("sbin/shell"))

        output_path = sandbox.root / "sbin/shell"
        assert output_path.read_bytes() == b"posix shell"
        assert output_path.exists()
        assert output_path.readlink() == Path("../bin/sh")
        assert sandbox.problems == []

    def test_create_symlink_target_outside_sandbox(self, sandbox: FileSystem):
        # /shell -> ../bin/sh
        sandbox.mkdir(Path("bin"))
        sandbox.write_bytes(Path("bin/sh"), b"posix shell")
        sandbox.create_symlink(Path("../bin/sh"), Path("/shell"))

        assert any(p for p in sandbox.problems if isinstance(p, LinkExtractionProblem))
        output_path = sandbox.root / "shell"
        assert not output_path.exists()
        assert not output_path.is_symlink()

    def test_create_symlink_absolute_paths(self, sandbox: FileSystem):
        sandbox.write_bytes(Path("target file"), b"test content")
        sandbox.create_symlink(Path("/target file"), Path("/symlink"))

        output_path = sandbox.root / "symlink"
        assert output_path.exists()
        assert output_path.readlink() == Path("target file")
        assert sandbox.problems == []

    def test_create_symlink_absolute_paths_self_referenced(self, sandbox: FileSystem):
        sandbox.mkdir(Path("/etc"))
        sandbox.create_symlink(Path("/etc/passwd"), Path("/etc/passwd"))

        output_path = sandbox.root / "etc/passwd"
        assert not output_path.exists()
        assert output_path.readlink() == Path("../etc/passwd")
        assert sandbox.problems == []

    def test_create_symlink_outside_sandbox(self, sandbox: FileSystem):
        sandbox.create_symlink(Path("target file"), Path("../symlink"))

        output_path = sandbox.root / "../symlink"
        assert not os.path.lexists(output_path)
        assert sandbox.problems

    def test_create_symlink_path_traversal(
        self, sandbox: FileSystem, sandbox_parent: Path
    ):
        """Document a remaining path traversal scenario through a symlink chain.

        unblob.extractor.fix_symlinks() exists to cover up cases like this.
        """
        (sandbox_parent / "outer-secret").write_text("private key")

        # The path traversal is possible because at the creation of "secret" "future" does not exist
        # so it is not yet possible to determine if it will be a symlink to be allowed or not.
        # When the order of the below 2 lines are changed, the path traversal is recognized and prevented.
        sandbox.create_symlink(Path("future/../outer-secret"), Path("secret"))
        sandbox.create_symlink(Path("."), Path("future"))

        assert sandbox.problems == []
        assert (sandbox.root / "secret").read_text() == "private key"

    def test_create_hardlink(self, sandbox: FileSystem):
        output_path = sandbox.root / "hardlink"
        linked_file = sandbox.root / "file"
        linked_file.write_bytes(b"")
        sandbox.create_hardlink(Path("file"), Path("hardlink"))

        assert output_path.stat().st_nlink == 2
        assert output_path.stat().st_ino == linked_file.stat().st_ino
        assert sandbox.problems == []

    def test_create_hardlink_absolute_paths(self, sandbox: FileSystem):
        output_path = sandbox.root / "hardlink"
        linked_file = sandbox.root / "file"
        linked_file.write_bytes(b"")
        sandbox.create_hardlink(Path("/file"), Path("/hardlink"))

        assert output_path.stat().st_nlink == 2
        assert output_path.stat().st_ino == linked_file.stat().st_ino
        assert sandbox.problems == []

    def test_create_hardlink_outside_sandbox(self, sandbox: FileSystem):
        output_path = sandbox.root / "../hardlink"
        linked_file = sandbox.root / "file"
        linked_file.write_bytes(b"")
        sandbox.create_hardlink(Path("file"), Path("../hardlink"))

        assert not os.path.lexists(output_path)
        assert sandbox.problems

    @pytest.mark.parametrize("path", [Path("ok-path"), Path("../outside-path")])
    def test_open(self, path: Path, sandbox: FileSystem):
        # can perform normal file operations
        with sandbox.open(path) as f:
            f.seek(100)
            f.write(b"text")
            assert f.tell() == 104
            f.seek(102)
            assert f.read(3) == b"xt"

        # and it is also persisted
        with sandbox.open(path, "rb+") as f:
            assert f.read() == bytes(100) + b"text"

    def test_open_no_path_traversal(self, sandbox: FileSystem):
        path = Path("file")
        with sandbox.open(path) as f:
            f.write(b"content")

        assert (sandbox.root / path).read_bytes() == b"content"
        assert sandbox.problems == []

    def test_open_outside_sandbox(self, sandbox: FileSystem):
        path = Path("../file")
        with sandbox.open(path) as f:
            f.write(b"content")

        assert not (sandbox.root / path).exists()
        assert sandbox.problems
        # the open is redirected to a lost+found directory, as path traversal is most probably a handler problem
        # and the extraction could be successful on real hw/fw, we just do not know where to extract
        real_out_path = ".unblob-lost+found/_e90583b491d2138aab0c8a12478ee050701910fd80c84289ae747e7c/file"
        assert (sandbox.root / real_out_path).read_bytes() == b"content"

    @pytest.mark.parametrize("path", [Path("ok-path"), Path("../outside-path")])
    def test_unlink(self, path: Path, sandbox: FileSystem):
        with sandbox.open(path) as f:
            f.write(b"content")
        sandbox.unlink(path)
        assert not (sandbox.root / path).exists()

    def test_unlink_no_path_traversal(self, sandbox: FileSystem):
        path = Path("file")
        with sandbox.open(path) as f:
            f.write(b"content")

        sandbox.unlink(path)
        assert not (sandbox.root / path).exists()
        assert sandbox.problems == []

    def test_unlink_outside_sandbox(self, sandbox: FileSystem):
        path = Path("../file")
        (sandbox.root / path).touch()
        sandbox.unlink(path)

        assert (sandbox.root / path).exists()
        assert sandbox.problems


@pytest.mark.parametrize(
    "input_path, expected_path",
    [
        # the important thing here is that there is a hash, that is different for different parents
        # even if they are reduced to the same slug
        pytest.param(
            "file",
            ".unblob-lost+found/_2727e5a04d8acc225b3320799348e34eff9ac515e1130101baab751a/file",
            id="non-traversal",
        ),
        pytest.param(
            "../file",
            ".unblob-lost+found/_e90583b491d2138aab0c8a12478ee050701910fd80c84289ae747e7c/file",
            id="path-traversal",
        ),
        pytest.param(
            "../../file",
            ".unblob-lost+found/_42a75ca4cfdad26e66c560d67ca640c8690ddbe20ba08e5e65d5733e/file",
            id="path-traversal-further-down",
        ),
        pytest.param(
            "/etc/passwd",
            ".unblob-lost+found/etc_feb0ca54f8477feb6210163efa5aa746160c573118847d96422b5dfa/passwd",
            id="absolute-path",
        ),
        pytest.param(
            "../m@u/n,g.e<d>p!a#t%h&t*o/file.md",
            ".unblob-lost+found/m-u-n-g-e-d-p-a-t-h-t-o_20bf817fac07c1c34418fcc37d153571577f9b67c5a0e5f0f63bcacb/file.md",
            id="non-alnum-path-parts",
        ),
    ],
)
def test_make_lost_and_found_path(input_path: str, expected_path: str):
    assert make_lost_and_found_path(Path(input_path)) == Path(expected_path)
