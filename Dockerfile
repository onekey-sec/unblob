FROM python:3.12-slim-bookworm

RUN mkdir -p /data/input /data/output
RUN useradd -m unblob
RUN chown -R unblob /data

WORKDIR /data/output

COPY install-deps.sh /
RUN sh -xeu /install-deps.sh

# You MUST do an uv build before to have the wheel to copy & install here (CI action will do this when building)
COPY dist/*.whl /tmp/
RUN pip --disable-pip-version-check install --upgrade pip
RUN pip install /tmp/unblob*.whl --prefix /usr/local

USER unblob
ENTRYPOINT ["unblob"]
