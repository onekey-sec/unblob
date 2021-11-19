# unblob - extract anything

unblob is an alternative to binwalk to inspect and/or extract any kind of
file format.

## Development

### Dependencies

We are using [poetry](https://python-poetry.org/) for managing dependencies.

`poetry install` will install all required dependencies in a virtualenv.

### Testing

We are using pytest for running our test suite.

To run all the tests, run `python -m pytest tests/` in the activated virtualenv.

### Linting

We are using [pre-commit](https://pre-commit.com/) for running checks.
Important commands:

- `pre-commit install` makes the pre-commit run automatically
  during git commits with git hooks.
- `pre-commit run --all-files` runs the pre-commit for everything.
