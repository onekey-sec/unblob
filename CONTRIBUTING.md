# Contributing to unblob

Thanks for taking the time to contribute! This document explains how to report issues, set up a development environment, and submit changes.

## Table of contents

- [Ways to contribute](#ways-to-contribute)
- [Reporting bugs](#reporting-bugs)
- [Suggesting features or new formats](#suggesting-features-or-new-formats)
- [Security vulnerabilities](#security-vulnerabilities)
- [Development environment](#development-environment)
- [Running the tests](#running-the-tests)
- [Code style and checks](#code-style-and-checks)
- [Writing a handler](#writing-a-handler)
- [Submitting a pull request](#submitting-a-pull-request)

---

## Ways to contribute

- **Report a bug** — something isn't working as expected.
- **Suggest a feature** — an idea that would improve unblob.
- **Request a new format** — a file format you'd like unblob to support.
- **Implement a handler or extractor** — add support for a format yourself.
- **Improve documentation** — fix typos, clarify explanations, add examples.

---

## Reporting bugs

Open a [bug report](https://github.com/onekey-sec/unblob/issues/new?template=bug-report-🐞.md) on GitHub. Please include:

- A clear description of the problem and how to reproduce it.
- The command you ran and the full error output.
- Environment details — OS, Python version, unblob version, and the output of:

  ```console
  unblob --show-external-dependencies
  ```

- A binary sample that triggers the bug, if possible. Make sure it does not contain sensitive information or NDA-protected material.

Search [existing issues](https://github.com/onekey-sec/unblob/issues) before opening a new one.

---

## Suggesting features or new formats

- For general feature ideas, open a [feature suggestion](https://github.com/onekey-sec/unblob/issues/new?template=feature-suggestion-💡.md).
- For new file format support, open a [format suggestion](https://github.com/onekey-sec/unblob/issues/new?template=format-suggestion-📦.md). Include a brief description of the format, sample files or references (specs, blog posts, hex dumps), and the motivation for adding it.

If you don't know how to implement a handler yourself, that's fine — open the issue anyway and the maintainers will consider it.

For longer discussions or usage questions, use [GitHub Discussions](https://github.com/onekey-sec/unblob/discussions).

---

## Security vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**
Follow the [security policy](https://github.com/onekey-sec/unblob/security/policy) instead.

---

## Development environment

### Prerequisites

| Tool | Purpose |
|------|---------|
| Python ≥ 3.10 | Runtime |
| [git](https://git-scm.com/download) | Version control |
| [uv](https://docs.astral.sh/uv/getting-started/installation/) | Python package management |
| [Rust toolchain](https://rustup.rs/) | Building native extensions |
| [Git LFS](https://git-lfs.github.com/) | Large integration test fixtures |
| [pre-commit](https://pre-commit.com/) | Automated checks on commit |

### Setup

#### Option A: Nix + direnv (recommended)

If you have [Nix](https://nixos.org/download/) and [direnv](https://direnv.net/) installed, the development shell is configured automatically. It provides Python, Rust, Node.js, all external extractor tools, and every other dependency — no manual steps required.

```console
git clone https://github.com/<your-username>/unblob.git
cd unblob
direnv allow
```

`direnv` picks up the `.envrc` at the repo root, which activates the Nix dev shell defined in `flake.nix`. The first run pulls pre-built derivations from the `unblob.cachix.org` binary cache, so it is fast even without a local Nix build.

If you need to customise the environment (e.g. disable the Nix shell or add local overrides), create a `.envrc.user` file in the repo root — it is sourced automatically and ignored by git.

Then set up Git LFS and install the pre-commit hooks:

```console
git lfs install
git lfs pull
uv run pre-commit install
```

#### Option B: manual setup

1. Fork the repository on GitHub, then clone your fork:

   ```console
   git clone https://github.com/<your-username>/unblob.git
   cd unblob
   ```

2. Install Git LFS and pull the tracked files:

   ```console
   git lfs install
   git lfs pull
   ```

3. Install all dependencies (including dev extras):

   ```console
   uv sync --all-extras --dev
   ```

4. Install the pre-commit hooks:

   ```console
   uv run pre-commit install
   ```

5. Install the [external extractor tools](https://unblob.org/installation/#install-extractors) required to run the full test suite.

---

## Running the tests

```console
uv run pytest tests/ -v
```

Tests are run against Python 3.10, 3.11, 3.12, 3.13, and 3.14 in CI. Integration test fixtures live in `tests/integration/` and are tracked by Git LFS — make sure LFS is set up before running them.

---

## Code style and checks

All checks run automatically on commit via pre-commit. To run them manually:

```console
uv run pre-commit run --all-files
```

Individual tools:

| Tool | Command | Purpose |
|------|---------|---------|
| [ruff](https://docs.astral.sh/ruff/) | `uv run ruff format .` / `uv run ruff check .` | Formatting and linting |
| [pyright](https://github.com/microsoft/pyright) | `uv run pyright` | Static type checking |

We follow PEP 8. Formatting is enforced by ruff so you don't need to think about it — just run the hooks.

---

## Writing a handler

The [development guide](https://unblob.org/development/) covers this in detail. The short version:

1. Pick the right base class:
   - `StructHandler` for formats with a fixed C-style header.
   - `Handler` for everything else.
   - `DirectoryHandler` for multi-file formats (e.g. multi-volume archives).

2. Create a file under `python/unblob/handlers/<type>/<name>.py`.

3. Define `NAME`, `PATTERNS` (Hyperscan `HexString` or `Regex` rules), `EXTRACTOR`, and implement `calculate_chunk()`.

4. Add integration tests in `tests/integration/<type>/<handler_name>/` with input files in `__input__/` and expected output in `__output__/`. Cover as many variants as possible (endianness, compression algorithms, padding, versions).

If you prefer to distribute your handler independently, you can use the [plugin system](https://unblob.org/development/#importing-handlers-through-plugins) via `--plugins-path`.

---

## Submitting a pull request

1. Create a branch from `main`:

   ```console
   git checkout -b my-feature
   ```

2. Make your changes. Keep commits focused and the diff reviewable.

3. Make sure all checks pass:

   ```console
   uv run pre-commit run --all-files
   uv run pytest tests/ -v
   ```

4. Push and open a pull request against `main`. Describe what the change does and link any related issues.

A maintainer will review the PR. For handler contributions, we'll check that the integration tests cover the format's main variants before merging.
