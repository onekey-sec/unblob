# pyright: reportUnusedExpression=false
# ruff: noqa: B018

import sys

import unblob.plugins
from unblob import cli
from unblob.file_utils import File, iterbits, round_down
from unblob.handlers.compression.lzo import HeaderFlags as LZOHeaderFlags
from unblob.models import _JSONEncoder
from unblob.parser import _HexStringToRegex
from unblob.report import ChunkReport, FileMagicReport, StatReport

_HexStringToRegex.literal
_HexStringToRegex.wildcard
_HexStringToRegex.jump
_HexStringToRegex.range_jump
_HexStringToRegex.alternative

_JSONEncoder.default

ChunkReport.handler_name
FileMagicReport.magic
FileMagicReport.mime_type
StatReport.is_link

sys.breakpointhook
cli.cli.context_class

unblob.plugins.hookimpl
File.from_bytes

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
