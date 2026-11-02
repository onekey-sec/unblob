# unblob handlers

Rules for handlers in `python/unblob/handlers/` and their tests in
`tests/handlers/` and `tests/integration/`. The root `AGENTS.md` and
`docs/development.md` (especially "Common unblob Handler Mistakes") apply too.

## Shape of a handler

- **Parser**: reads and validates the structure; writes no files and holds
  no `FileSystem`. Parse in `parse()` or a `parse(file, offset)` classmethod
  on a frozen dataclass, not in `__init__`.
- **Extractor** (`Extractor.extract` / `DirectoryExtractor.extract`): writes
  the children and records problems. Keep no per-chunk state on `self`:
  unblob shares one extractor instance across chunks.
- **Handler** (`calculate_chunk`): parses, validates and returns a
  `ValidChunk` with the chunk's metadata.
- Functions used by one class belong in that class.
- Put the handler in `python/unblob/handlers/<category>/<name>.py` and
  register it in `BUILTIN_HANDLERS` (or `BUILTIN_DIR_HANDLERS`) in
  `python/unblob/handlers/__init__.py`.

## Parsing

- Describe on-disk structures with `StructHandler` / `StructParser` C
  definitions and read fields by name, not hand-written offsets, masks or
  slices. dissect.cstruct supports bitfields, `uint24` and arrays sized by
  an earlier field.
- Don't name a C definition field `size`: it shadows cstruct's generated
  `.size` (a pre-commit hook rejects it).
- `StructParser.parse` takes a `File` or `bytes`; from other streams, read
  the exact header size and parse the bytes.
- Use `IntEnum` / `IntFlag` for spec codes. Keep file values as plain `int`
  where vendors may add values: `IntEnum(value)` raises on unknown ones.
- Pass an explicit whence (`io.SEEK_*`) to `seek()`.
- Cite the spec or reference implementation next to the structures, pinned
  to a commit or version.

## Sizes, bounds and errors

- Validate header fields (version, sizes, offsets) before trusting them.
- Take sizes from the structures, never from the file size. Don't clip to
  the file or check `file.size()`: unblob drops chunks that run past the
  end, which leaves truncated input unknown.
- On malformed input, raise `InvalidInputFormat` with a message, using
  `from exc` when re-raising. Let `InvalidInputFormat`, `EOFError` and
  `SeekError` propagate from `calculate_chunk`; catch only when probing
  candidate locations or formats.
- Corrupt input may fail the whole extraction, but never silently: raise or
  record an `ExtractionProblem`.

## Which checks to keep

Handlers run on every pattern match in arbitrary data; judge a check by
what a false match or crafted input does without it.

- Keep format gates (strict reserved or undefined fields included),
  resource limits, and checks that protect chunk bounds, carved content or
  paths.
- Drop a check only if another check rejects the same input, and name it.
  "Valid input never fails it" is no reason to drop a check.
- Don't re-check a magic the pattern already matched.
- Bound counts read from a header before walking their entries, even with a
  checksum: weak or partial checksums pass on random data.
- Don't repeat what unblob already rejects: chunks that end at or before
  their start or past the file, and truncated struct parses (cstruct raises
  `EOFError`). A plain `file.read(n)` returns short data silently; check its
  length.

## Checksums

Rejecting on a checksum mismatch is a per-format trade-off. Keep an existing
handler's policy unless the task is to change it. For a new handler, choose
from the trade-off below and state the choice in the commit message; ask the
user when it stays ambiguous.

- Rejecting cuts false positives: worth it for weak patterns with few gates
  when corruption is unlikely.
- Ignoring, or recording an `ExtractionProblem`, still extracts corrupted or
  patched content; this is unblob's default leaning.
- Middle ground: gate on a header checksum, extract despite a payload
  mismatch.
- Hash large data in a stream; test both match and mismatch.

## Layering

- One container per handler: write the children as files and let unblob's
  pattern search find nested formats. Don't parse the next layer.
- Prefer one chunk per self-delimiting unit (block, image, signed envelope)
  over walking chains; unblob resumes scanning after each chunk.
- Stop where the enclosing format belongs to another handler.
- When one carved file needs a sibling, use a `DirectoryHandler`.
- A chunk with nothing to unpack is found again in its own output, down to
  the depth limit: override `ValidChunk.extract` to do nothing when
  `is_whole_file` (see `ElfChunk`).

## Memory and resource limits

- Don't read whole files or partitions into memory: open with
  `File.from_path`, carve with `FileSystem.carve` / `carve_chunk_to_file`,
  read with `iterate_file`.
- Wrap in-memory data in `io.BytesIO`, not `File.from_bytes`, which copies
  it.
- Bound every size from the input before allocating or decompressing; pass
  `max_length` to `zlib.decompressobj().decompress` / `LZMADecompressor`
  and check declared sizes before calling C decompressors.
- Write output through `FileSystem`, which keeps paths inside the
  extraction directory; never join paths from the input yourself.

## Metadata and problems

- Report metadata only where it has a known use, not data already visible
  in the output (sizes, offsets, names).
- Report from `calculate_chunk`; from extraction only when the data exists
  only after decoding, with a comment saying why.
- Record an `ExtractionProblem` with a `resolution` when something could
  not be extracted as intended (failed decompression, encryption, a
  checksum mismatch extracted anyway).

## `HandlerDoc`

- `description`: what the handler finds, extracts and reports, as
  concatenated string pieces.
- `limitations`: only what the handler cannot handle; behavior belongs in
  the description.
- `references`: pinned links.
- After changing a `HandlerDoc`, regenerate `docs/handlers.md` (see the
  root `AGENTS.md`).

## Tests

- Unit tests in `tests/handlers/<category>/` build synthetic inputs; shared
  helpers go in `python/unblob/testing.py`. Test chunk bounds, extracted
  files and reports.
- Every check has a test: one parametrized rejection test per handler with a
  row per gate, plus own tests for checks real images depend on (skipped
  unused entries, checksum variants).
- Test a valid instance embedded at a nonzero offset between other data,
  a truncated instance, and malformed lengths and counts.
- Mutate a scratch copy to see each test fail without its check. Don't test
  with timeouts.
- Integration tests live in `tests/integration/<category>/<module>/`, or
  `.../<module>/<NAME>/` when the module name differs from the handler's
  `NAME`, with `__input__/` and `__output__/` (Git LFS); `test_handlers.py`
  fails for handlers without them. Cover the format's variants (endianness,
  versions, compression, padding). Regenerate `__output__/` when the output
  changes and review the diff.
- For changes to existing handlers, run unblob before and after on
  representative samples when available and compare extracted hashes,
  reports and run time; say so when no samples were available. Run at most
  two unblob instances, with a low `-p`, under `nice -n 19`: each forks one
  worker per core.
