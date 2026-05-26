import io
from pathlib import Path

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
LABEL_HEADER_SIZE = 32


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
            break
    return " ".join(parts)


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

    def extract(self, inpath: Path, outdir: Path) -> ExtractResult:
        fs = FileSystem(outdir)
        with File.from_path(inpath) as file:
            file.seek(SECTOR_SIZE, io.SEEK_SET)
            label = self._struct_parser.parse("lvm_label_header_t", file, Endian.LITTLE)

            file.seek(SECTOR_SIZE + label.header_size, io.SEEK_SET)
            pv_header = self._struct_parser.parse(
                "lvm_pv_header_t", file, Endian.LITTLE
            )

            data_areas = self._read_descriptors(file)
            metadata_areas = self._read_descriptors(file)
            mda_offset = metadata_areas[0].area_offset

            file.seek(mda_offset, io.SEEK_SET)
            mda = self._struct_parser.parse(
                "lvm_metadata_area_header_t", file, Endian.LITTLE
            )

            locn = mda.locns[0]
            file.seek(mda_offset + locn.data_offset, io.SEEK_SET)
            text = file.read(locn.data_size).decode("utf-8")
            metadata = parse_lvm_metadata(text)

            vg = self._get_vg(metadata)
            pv_name = self._get_pv_name(vg, pv_header.uuid.decode("ascii"))
            extent_bytes = vg["extent_size"] * SECTOR_SIZE
            pe_start = data_areas[0].area_offset

            for lv_name, lv in vg.get("logical_volumes", {}).items():
                self._extract_lv(file, fs, lv_name, lv, pv_name, pe_start, extent_bytes)

        return ExtractResult(reports=fs.problems)

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
        extent_bytes: int,
    ):
        out_path = Path(f"{lv_name}.img")
        with fs.open(out_path, "wb+") as outfile:
            for key, seg in lv.items():
                # filter to segment sub-sections; "segment_count" also matches the prefix but is an int
                if not (key.startswith("segment") and isinstance(seg, dict)):
                    continue
                # stripe_count == 1 is the only directly extractable shape (linear); anything else needs reassembly
                if seg.get("stripe_count") != 1:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"{lv_name}/{key}: unsupported segment (type={seg.get('type')!r})",
                            resolution="Segment skipped, output file will have a gap.",
                        )
                    )
                    continue
                if seg["stripes"][0] != pv_name:
                    fs.record_problem(
                        ExtractionProblem(
                            problem=f"{lv_name}/{key}: segment lives on foreign PV {seg['stripes'][0]!r}",
                            resolution="Segment skipped, output file will have a gap.",
                        )
                    )
                    continue

                pe_index = seg["stripes"][1]
                start_extent = seg["start_extent"]
                extent_count = seg["extent_count"]

                src = pe_start + pe_index * extent_bytes
                dst = start_extent * extent_bytes
                length = extent_count * extent_bytes

                outfile.seek(dst, io.SEEK_SET)
                for chunk in iterate_file(file, src, length):
                    outfile.write(chunk)

    def _read_descriptors(self, file: File) -> list:
        descs = []
        while True:
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
            "Only linear segments (striped with stripe_count=1) are supported. Other segment types (multi-stripe, mirror, raid, thin, snapshot, cache) require cross-PV reassembly or a separate format parser",
        ],
    )

    def is_valid_header(self, header, start_offset: int) -> bool:
        return (
            LABEL_HEADER_SIZE <= header.header_size <= SECTOR_SIZE
            and header.sector * SECTOR_SIZE <= start_offset
        )

    def calculate_chunk(self, file: File, start_offset: int) -> ValidChunk | None:
        header = self.parse_header(file, Endian.LITTLE)

        if not self.is_valid_header(header, start_offset):
            raise InvalidInputFormat("Invalid LVM label header.")

        pv_start = start_offset - header.sector * SECTOR_SIZE

        file.seek(start_offset + header.header_size, io.SEEK_SET)
        pv_header = self.cparser_le.lvm_pv_header_t(file)

        if pv_header.device_size == 0:
            raise InvalidInputFormat("LVM PV has zero device size.")

        return ValidChunk(
            start_offset=pv_start,
            end_offset=pv_start + pv_header.device_size,
        )
