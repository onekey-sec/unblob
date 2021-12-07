FROM python:3.8-slim

WORKDIR /app
RUN mkdir -p /data/input /data/output
RUN useradd --home-dir /app unblob

ENTRYPOINT ["/app/.venv/bin/unblob"]

RUN apt-get update && apt-get install --no-install-recommends -y \
    unar \
    gcc \
    zlib1g-dev \
    liblzo2-dev \
    lziprecover \
    lzop \
    lz4 \
    squashfs-tools \
    p7zip-full

COPY pyproject.toml /app
COPY poetry.lock /app
COPY unblob/ /app/unblob/

# This will make the Project virtualenv in /app/.venv
# See: https://python-poetry.org/docs/configuration/#virtualenvsin-project-boolean
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
RUN pip install poetry
RUN poetry install --no-dev

WORKDIR /data/output
RUN chown -R unblob /app /data
USER unblob
