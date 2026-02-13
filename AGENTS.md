# Repository Guidelines

## Project Structure & Module Organization
- `python/unblob/`: Python package, CLI, core logic, handlers.
- `python/unblob/handlers/`: format handlers by category (e.g., `archive`, `filesystem`, `compression`).
- `rust/`: Rust extension module built via `maturin`.
- `tests/`: unit and integration tests; large fixtures in `tests/integration/` via Git LFS.
- `docs/`: MkDocs docs.
- `fuzzing/`: fuzz harnesses.

## Build, Test, and Development Commands
- `uv sync --all-extras --dev`: install dev dependencies into a managed virtualenv.
- `direnv allow`: enable the local environment (uses `nix` to provide dependencies).
- `direnv reload`: reload the environment after changes to Nix or env files.
- `uv run unblob --help`: run the CLI inside the `uv` environment.
- `uv run unblob --build-handlers-doc docs/handlers.md`: auto-generate handler documentation; required when adding a new handler.
- `uv run pytest tests -v`: run the test suite with verbose output.
- `python -m pytest tests/`: alternative test invocation when the virtualenv is already active.
- `pre-commit run --all-files`: run formatting, linting, and static checks locally.

## Coding Style & Naming Conventions
- Python uses 4-space indentation and standard library `pathlib` style for filesystem paths.
- Formatting and linting are enforced via `pre-commit` and `ruff`; do not bypass failing hooks.
- Type checks use `pyright` (standard mode).
- Use `snake_case` for functions/modules, `PascalCase` for classes, and keep handler names descriptive.
- New handlers should live under `python/unblob/handlers/<category>/` and be named after the format.

## Handler Guidelines
- Follow PEP 8 and rely on `ruff format`/`ruff check` via `pre-commit` for consistent style.
- Prefer specific, non-overlapping patterns to minimize false positives and processing.
- Avoid checksum validation unless false positives require it; use `seek()` carefully, restore offsets, and guard against negative seeks or signedness bugs.

## Testing Guidelines
- Tests use `pytest`; coverage is enforced with `--cov --cov-fail-under=90`.
- Integration fixtures are in `tests/integration/` and require Git LFS to be installed and pulled.
- Add integration inputs under `tests/integration/<type>/<format>/__input__/`.
- Generate expected extraction output with:
  ```
  find tests/integration/<type>/<format>/__input__ -type f -print -exec uv run unblob -vvv -f -k -e tests/integration/<type>/<format>/__output__ {} \;
  ```
- Integration tests should cover variants (block size, compression types, endianness, versions).
- Prefer samples with padding prefix and suffix to validate start offset detection.
- Name tests `test_*.py` and keep new tests alongside the feature area they validate.

## Commit & Pull Request Guidelines
- Follow the existing commit style: `type(scope): summary` (examples: `feat(handler): ...`, `chore: ...`).
- Use `revert "..."` when reverting a specific change.
- PRs should include a concise summary, test results, and link any related issues.
- Include documentation updates when behavior or CLI output changes.

## Security & Reporting
- Report security issues using the process in `SECURITY.md` rather than opening public issues.
