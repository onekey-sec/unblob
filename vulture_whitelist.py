# pyright: reportUnusedExpression=false
# ruff: noqa: B018

import sys

import unblob.plugins
from unblob import cli
from unblob.doc import generate_markdown
from unblob.file_utils import File, FileSystem, iterbits, round_down
from unblob.handlers.compression.lzo import HeaderFlags as LZOHeaderFlags
from unblob.models import (
    Handler,
    HandlerDoc,
    HandlerType,
    ReportModelAdapter,
    SingleFile,
    TaskResult,
)
from unblob.parser import _HexStringToRegex
from unblob.report import (
    ChunkReport,
    ExtractCommandFailedReport,
    FileMagicReport,
    StatReport,
    UnknownErrorBase,
)

_HexStringToRegex.literal
_HexStringToRegex.wildcard
_HexStringToRegex.jump
_HexStringToRegex.range_jump
_HexStringToRegex.alternative

TaskResult.filter_reports
ChunkReport.handler_name
FileMagicReport.magic
FileMagicReport.mime_type
StatReport.is_link

SingleFile

sys.breakpointhook
cli.cli.context_class

unblob.plugins.hookimpl
File.from_bytes
File.readable
File.writable
File.seekable
FileSystem.open

iterbits
round_down

LZOHeaderFlags.DOSISH
LZOHeaderFlags.H_EXTRA_FIELD
LZOHeaderFlags.H_GMTDIFF
LZOHeaderFlags.H_PATH
LZOHeaderFlags.MULTIPART
LZOHeaderFlags.NAME_DEFAULT
LZOHeaderFlags.STDIN
LZOHeaderFlags.STDOUT

HandlerType.ARCHIVE
HandlerType.EXECUTABLE
HandlerType.COMPRESSION
HandlerType.FILESYSTEM
HandlerType.BAREMETAL
HandlerType.BOOTLOADER
HandlerType.ENCRYPTION

HandlerDoc
generate_markdown

Handler.DOC

ReportModelAdapter

report_type

UnknownErrorBase.model_config
UnknownErrorBase.model_post_init

ExtractCommandFailedReport.encode_bytes
ExtractCommandFailedReport.decode_bytes
