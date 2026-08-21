import binascii
import io
from pathlib import Path
from typing import BinaryIO

from unblob.file_utils import (
    Endian,
    FileSystem,
    InvalidInputFormat,
    StructParser,
    iterate_file,
)
from unblob.models import (
    Extractor,
    ExtractResult,
    File,
    HandlerDoc,
    HandlerType,
    HexString,
    Reference,
    StructHandler,
    ValidChunk,
)
from unblob.report import ExtractionProblem

C_DEFINITION = r"""
        typedef struct lvm_label_header {
            char     signature[8];   // "LABELONE"
            uint64   sector;         // sector number of this label header, usually 1
            uint32   crc;            // CRC of fields below to end of sector
            uint32   header_size;    // size of this header; pv_header follows immediately
            char     type[8];        // "LVM2 001"
        } lvm_label_header_t;

        typedef struct lvm_pv_header {
            char     uuid[32];       // PV UUID, ASCII
            uint64   device_size;    // PV size in bytes
        } lvm_pv_header_t;

        typedef struct lvm_data_area_descriptor {
            uint64   area_offset;    // relative to start of the PV
            uint64   area_size;      // 0 = unbounded
        } lvm_data_area_descriptor_t;

        typedef struct lvm_raw_location_descriptor {
            uint64   data_offset;    // relative to start of metadata area
            uint64   data_size;
            uint32   crc;
            uint32   flags;          // 0x1 = ignored
        } lvm_raw_location_descriptor_t;

        typedef struct lvm_metadata_area_header {
            uint32                          crc;
            char                            magic[16];   // "\x20LVM2\x20x[5A%r0N*>" signature
            uint32                          version;
            uint64                          offset;      // metadata area offset from PV start
            uint64                          size;        // metadata area size
            lvm_raw_location_descriptor_t   locns[4];
            char                            padding[376];
        } lvm_metadata_area_header_t;

    """

SECTOR_SIZE = 512  # LVM2 format constant
LABEL_SCAN_SECTORS = 4
LABEL_HEADER_SIZE = 32
PV_HEADER_SIZE = 40
DESCRIPTOR_SIZE = 16
MDA_MAGIC = b" LVM2 x[5A%r0N*>"
MDA_VERSION = 1
INITIAL_CRC = 0xF597A6CF
RAW_LOCATION_IGNORED = 0x1


def _lvm_crc32(data: bytes | bytearray) -> int:
    """Calculate LVM's non-inverted, seeded CRC-32."""
    return (binascii.crc32(data, INITIAL_CRC ^ 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def parse_lvm_metadata(text: str) -> dict:
    """Parse LVM2 text metadata into nested dicts.

    Grammar (per libvslvm §5.5):
        section { ... }                section opens a named scope
        key = value                    int, "string", or [list]
        # ...                          comment to end of line
    Lists may span multiple lines until ']'.
    """
    root: dict = {}
    stack: list[dict] = [root]
    lines = _clean(text)

    for line in lines:
        if line == "}":
            if len(stack) == 1:
                raise InvalidInputFormat("Unexpected closing brace in LVM metadata.")
            stack.pop()
        elif line.endswith("{"):
            section: dict = {}
            stack[-1][line[:-1].strip()] = section
            stack.append(section)
        elif "=" in line:
            key, _, value = (s.strip() for s in line.partition("="))
            if value.startswith("[") and "]" not in value:
                value = _consume_list(value, lines)
            stack[-1][key] = _parse_value(value)

    if len(stack) != 1:
        raise InvalidInputFormat("Unclosed section in LVM metadata.")
    return root


def _clean(text: str):
    """Yield non-empty, comment-stripped lines."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            yield line


def _consume_list(first: str, lines) -> str:
    """Join continuation lines until ']' is seen, return the full list value as one string."""
    parts = [first]
    for line in lines:
        parts.append(line)
        if "]" in line:
            return " ".join(parts)
    raise InvalidInputFormat("Unclosed list in LVM metadata.")


def _parse_value(text: str) -> int | str | list:
    if text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    if text.startswith("[") and text.endswith("]"):
        items = [chunk.strip() for chunk in text[1:-1].split(",")]
        return [_parse_value(item) for item in items if item]
    if text.lstrip("-").isdigit():
        return int(text)
    return text


class LVM2Extractor(Extractor):
    def __init__(self):
        self._struct_parser = StructParser(C_DEFINITION)

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:  # noqa: C901
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            label = self._find_label(file)
            label_offset = label.sector * SECTOR_SIZE

            file.seek(label_offset + label.header_size, io.SEEK_SET)
            pv_header = self._struct_parser.parse(
                "lvm_pv_header_t", file, Endian.LITTLE
            )
            if pv_header.device_size > file.size():
                raise InvalidInputFormat("LVM PV size exceeds the input size.")

            label_end = label_offset + SECTOR_SIZE
            data_areas = self._read_descriptors(file, label_end)
            metadata_areas = self._read_descriptors(file, label_end)
            if not data_areas:
                raise InvalidInputFormat("LVM PV has no data area.")
            if not metadata_areas:
                raise InvalidInputFormat("LVM PV has no metadata area.")

            data_area = data_areas[0]
            self._validate_area(data_area, pv_header.device_size, "data")
            metadata_area = metadata_areas[0]
            self._validate_area(metadata_area, pv_header.device_size, "metadata")
            mda_offset = metadata_area.area_offset

            file.seek(mda_offset, io.SEEK_SET)
            mda = self._struct_parser.parse(
                "lvm_metadata_area_header_t", file, Endian.LITTLE
            )
            self._validate_mda(
                file, mda, mda_offset, metadata_area, pv_header.device_size
            )

            locn = next(
                (
                    location
                    for location in mda.locns
                    if location.data_offset
                    and location.data_size
                    and not location.flags & RAW_LOCATION_IGNORED
                ),
                None,
            )
            if locn is None:
                raise InvalidInputFormat("LVM metadata area has no usable location.")

            text = self._decode_metadata(file, mda_offset, mda.size, locn)
            metadata = parse_lvm_metadata(text)

            vg = self._get_vg(metadata)
            try:
                pv_name = self._get_pv_name(vg, pv_header.uuid.decode("ascii"))
            except UnicodeDecodeError as e:
                raise InvalidInputFormat(
                    "LVM physical volume UUID is not ASCII encoded"
                ) from e
            extent_size = vg.get("extent_size")
            if not isinstance(extent_size, int) or extent_size <= 0:
                raise InvalidInputFormat("LVM volume group has invalid extent size.")
            extent_bytes = extent_size * SECTOR_SIZE
            pe_start = data_area.area_offset
            data_area_size = data_area.area_size or pv_header.device_size - pe_start

            logical_volumes = vg.get("logical_volumes")
            if not isinstance(logical_volumes, dict):
                raise InvalidInputFormat("LVM volume group has invalid logical volumes")

            for lv_name, lv in logical_volumes.items():
                self._extract_lv(
                    file,
                    fs,
                    lv_name,
                    lv,
                    pv_name,
                    pe_start,
                    data_area_size,
                    extent_bytes,
                )

        return ExtractResult(reports=fs.problems)

    def _find_label(self, file: File):
        for sector in range(LABEL_SCAN_SECTORS):
            label_offset = sector * SECTOR_SIZE
            file.seek(label_offset, io.SEEK_SET)
            if file.read(8) != b"LABELONE":
                continue

            file.seek(label_offset, io.SEEK_SET)
            label = self._struct_parser.parse("lvm_label_header_t", file, Endian.LITTLE)
            if (
                label.sector == sector
                and LABEL_HEADER_SIZE
                <= label.header_size
                <= SECTOR_SIZE - PV_HEADER_SIZE
                and label.type == b"LVM2 001"
                and self._valid_label_crc(file, label_offset, label.crc)
            ):
                return label

        raise InvalidInputFormat("LVM label not found in the first four sectors.")

    @staticmethod
    def _valid_label_crc(file: File, label_offset: int, expected_crc: int) -> bool:
        file.seek(label_offset + 20, io.SEEK_SET)
        return _lvm_crc32(file.read(SECTOR_SIZE - 20)) == expected_crc

    @staticmethod
    def _read_metadata(file: File, mda_offset: int, mda_size: int, locn) -> bytes:
        if (
            mda_size < SECTOR_SIZE
            or not SECTOR_SIZE <= locn.data_offset < mda_size
            or locn.data_size > mda_size - SECTOR_SIZE
        ):
            raise InvalidInputFormat("Invalid LVM metadata location.")

        first_size = min(locn.data_size, mda_size - locn.data_offset)
        file.seek(mda_offset + locn.data_offset, io.SEEK_SET)
        data = file.read(first_size)

        remaining = locn.data_size - first_size
        if remaining:
            file.seek(mda_offset + SECTOR_SIZE, io.SEEK_SET)
            data += file.read(remaining)

        if len(data) != locn.data_size:
            raise InvalidInputFormat("Truncated LVM metadata location.")
        return data

    @staticmethod
    def _decode_metadata(file: File, mda_offset: int, mda_size: int, locn) -> str:
        data = LVM2Extractor._read_metadata(file, mda_offset, mda_size, locn)
        if _lvm_crc32(data) != locn.crc:
            raise InvalidInputFormat("Invalid LVM metadata checksum.")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InvalidInputFormat("LVM metadata is not valid UTF-8.") from exc

    @staticmethod
    def _validate_mda(file: File, mda, mda_offset: int, area, pv_size: int) -> None:
        file.seek(mda_offset + 4, io.SEEK_SET)
        if (
            _lvm_crc32(file.read(SECTOR_SIZE - 4)) != mda.crc
            or mda.magic != MDA_MAGIC
            or mda.version != MDA_VERSION
            or mda.offset != mda_offset
            or mda.size < SECTOR_SIZE
            or mda.size > pv_size - mda_offset
            or (area.area_size and mda.size > area.area_size)
        ):
            raise InvalidInputFormat("Invalid LVM metadata area header.")

    @staticmethod
    def _validate_area(area, pv_size: int, area_name: str) -> None:
        if area.area_offset >= pv_size or (
            area.area_size and area.area_size > pv_size - area.area_offset
        ):
            raise InvalidInputFormat(f"Invalid LVM {area_name} area descriptor.")

    @staticmethod
    def _get_vg(metadata: dict) -> dict:
        """Locate the VG block — the only top-level value that is a dict."""
        for body in metadata.values():
            if isinstance(body, dict):
                return body
        raise InvalidInputFormat("LVM metadata has no volume group block.")

    @staticmethod
    def _get_pv_name(vg: dict, pv_uuid: str) -> str:
        """Match the binary PV UUID to the metadata's physical_volumes entry."""
        for name, body in vg["physical_volumes"].items():
            if body["id"].replace("-", "") == pv_uuid:
                return name
        raise InvalidInputFormat("PV UUID not found in volume group metadata.")

    def _extract_lv(
        self,
        file: File,
        fs: FileSystem,
        lv_name: str,
        lv: dict,
        pv_name: str,
        pe_start: int,
        data_area_size: int,
        extent_bytes: int,
    ):
        out_path = Path(f"{lv_name}.img")
        with fs.open(out_path, "wb+") as outfile:
            for key, seg in lv.items():
                # filter to segment sub-sections; "segment_count" also matches the prefix but is an int
                if not (key.startswith("segment") and isinstance(seg, dict)):
                    continue
                self._extract_segment(
                    file,
                    outfile,
                    fs,
                    lv_name,
                    key,
                    seg,
                    pv_name,
                    pe_start,
                    data_area_size,
                    extent_bytes,
                )

    @staticmethod
    def _extract_segment(
        file: File,
        outfile: BinaryIO,
        fs: FileSystem,
        lv_name: str,
        key: str,
        seg: dict,
        pv_name: str,
        pe_start: int,
        data_area_size: int,
        extent_bytes: int,
    ) -> None:
        resolution = "Segment skipped, output file will have a gap."
        if seg.get("type") not in {"linear", "striped"} or seg.get("stripe_count") != 1:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"{lv_name}/{key}: unsupported segment (type={seg.get('type')!r})",
                    resolution=resolution,
                )
            )
            return

        stripes = seg.get("stripes")
        if not (
            isinstance(stripes, list)
            and len(stripes) == 2
            and isinstance(stripes[0], str)
            and isinstance(stripes[1], int)
            and stripes[1] >= 0
        ):
            fs.record_problem(
                ExtractionProblem(
                    problem=f"{lv_name}/{key}: invalid stripes list",
                    resolution=resolution,
                )
            )
            return
        if stripes[0] != pv_name:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"{lv_name}/{key}: segment lives on foreign PV {stripes[0]!r}",
                    resolution=resolution,
                )
            )
            return

        start_extent = seg.get("start_extent")
        extent_count = seg.get("extent_count")
        if not (
            isinstance(start_extent, int)
            and start_extent >= 0
            and isinstance(extent_count, int)
            and extent_count > 0
        ):
            fs.record_problem(
                ExtractionProblem(
                    problem=f"{lv_name}/{key}: invalid extent range",
                    resolution=resolution,
                )
            )
            return

        pe_index = stripes[1]
        src = pe_start + pe_index * extent_bytes
        dst = start_extent * extent_bytes
        length = extent_count * extent_bytes
        relative_end = pe_index * extent_bytes + length
        if relative_end > data_area_size:
            fs.record_problem(
                ExtractionProblem(
                    problem=f"{lv_name}/{key}: segment exceeds the local PV data area",
                    resolution=resolution,
                )
            )
            return

        outfile.seek(dst, io.SEEK_SET)
        for chunk in iterate_file(file, src, length):
            outfile.write(chunk)

    def _read_descriptors(self, file: File, end_offset: int) -> list:
        descs = []
        while True:
            if file.tell() + DESCRIPTOR_SIZE > end_offset:
                raise InvalidInputFormat("Unterminated LVM area descriptor list.")
            d = self._struct_parser.parse(
                "lvm_data_area_descriptor_t", file, Endian.LITTLE
            )
            if d.area_offset == 0 and d.area_size == 0:
                return descs
            descs.append(d)


class LVM2Handler(StructHandler):
    NAME = "lvm2"

    PATTERNS = [
        HexString("""
                  4c 41 42 45 4c 4f 4e 45 // LABELONE
                   [16] // sector(8) + crc(4) + data_offset(4)
                  4c 56 4d 32 20 30 30 31 // LVM2 001
                  """),
    ]
    EXTRACTOR = LVM2Extractor()
    C_DEFINITIONS = C_DEFINITION

    HEADER_STRUCT = "lvm_label_header_t"

    DOC = HandlerDoc(
        name="LVM2",
        description="LVM2 (Logical Volume Manager 2) is a volume management system for Linux block storage, grouping physical volumes (PVs) into volume groups (VGs) that expose logical volumes (LVs) as resizable virtual block devices. Each PV carries text-format metadata describing the VG layout and a data area holding LV contents as fixed-size physical extents.",
        handler_type=HandlerType.FILESYSTEM,
        vendor=None,
        references=[
            Reference(
                title="LVM2 on-disk format (libvslvm)",
                url="https://github.com/libyal/libvslvm/blob/main/documentation/Logical%20Volume%20Manager%20(LVM)%20format.asciidoc",
            ),
        ],
        limitations=[
            "Multi-PV volume groups produce one partial LV image per PV chunk. The data is preserved across all extractions, but combining the partials into a single LV image is left to the user.",
            "Only linear segments (striped with stripe_count=1) are supported. Other segment types (multi-stripe, mirror, raid, thin, snapshot, cache) require cross-PV reassembly or a separate format parser.",
        ],
    )

    def is_valid_header(self, header, start_offset: int) -> bool:
        return (
            header.sector < LABEL_SCAN_SECTORS
            and LABEL_HEADER_SIZE <= header.header_size <= SECTOR_SIZE - PV_HEADER_SIZE
            and header.sector * SECTOR_SIZE <= start_offset
        )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.LITTLE)

        if not self.is_valid_header(header, start_offset):
            raise InvalidInputFormat("Invalid LVM label header.")

        pv_start = start_offset - header.sector * SECTOR_SIZE

        file.seek(start_offset + 20, io.SEEK_SET)
        if _lvm_crc32(file.read(SECTOR_SIZE - 20)) != header.crc:
            raise InvalidInputFormat("Invalid LVM label checksum.")

        file.seek(start_offset + header.header_size, io.SEEK_SET)
        pv_header = self.cparser_le.lvm_pv_header_t(file)

        pv_end = pv_start + pv_header.device_size
        if pv_header.device_size == 0 or pv_end > file.size():
            raise InvalidInputFormat("Invalid LVM PV device size.")

        return ValidChunk(
            start_offset=pv_start,
            end_offset=pv_end,
        )
