# unblob

Read `docs/development.md` before changing handlers or extractors. When
working on handlers or their tests (`tests/handlers/`, `tests/integration/`),
follow `python/unblob/handlers/AGENTS.md` too.

## Environment

The Nix dev shell (`flake.nix`, loaded by direnv via `.envrc`) provides
Python, Rust and every external extractor. If a tool is missing, first retry
with `direnv exec . <cmd>`. Do not install tools with
pip, cargo or a system package manager.

Look things up locally before searching the web: run `<command> --help`, read
the man page or read the source. Never run `find` on a huge tree such as `/`,
`/nix` or `~`. If you run a script more than once, save it to a file and run
the file.

## Commands

- Tests: `uv run pytest tests/` (add `-k <name>` to narrow it down).
- Rust tests: `cargo test`, as in CI. Python tests and clippy don't replace
  them.
- All checks: `uv run pre-commit run --all-files` (ruff, cargo fmt/clippy,
  vulture, ...). Types are not in pre-commit: run `uv run pyright` too.
- Handler docs: after changing a `HandlerDoc`, regenerate `docs/handlers.md`
  with `uv run unblob --build-handlers-doc docs/handlers.md`.

## Generated files

Never edit generated files by hand: `docs/handlers.md` and
`python/unblob/_rust/*.pyi` (written by `maturin generate-stubs` in
pre-commit). If you can't run the generator, leave them unchanged and tell
the user which command to run.

## Git LFS

Integration test inputs and outputs under `tests/integration/` are in Git
LFS. If a test reads an LFS pointer file instead of data, fetch the fixtures
with `git lfs pull`, then rerun the affected tests.

## Commits

Use conventional commits scoped to the area, e.g. `feat(handler): add LZFSE
handler`, `fix(squashfs): ...`, `test(gif): add integration test fixtures`.
Describe the format and design decisions in the commit message.

## Public repository

unblob is public. Don't commit firmware samples you can't redistribute,
customer or vendor-confidential data, or internal names, URLs and paths.
Build test inputs synthetically or from freely licensed sources.
