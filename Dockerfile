FROM python:3.14-slim-bookworm

RUN mkdir -p /data/input /data/output
RUN useradd -m unblob
RUN chown -R unblob /data

WORKDIR /data/output

# Enable backports, required to get upx package
RUN printf "deb http://deb.debian.org/debian bookworm-backports main\n" \
    > /etc/apt/sources.list.d/backports.list

COPY install-deps.sh /
RUN sh -xeu /install-deps.sh

# You MUST do an uv build before to have the wheel to copy & install here (CI action will do this when building)
COPY dist/*.whl /tmp/
# lzfse has no CPython 3.14 wheel, so pip must compile it from source. Keep the
# compiler in this layer only; the extracted extension remains after it is purged.
RUN pip --disable-pip-version-check install --upgrade pip \
    && apt-get update \
    && apt-get install --no-install-recommends -y gcc libc6-dev \
    && pip install /tmp/unblob*.whl --prefix /usr/local \
    && apt-get purge --auto-remove -y gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

USER unblob
ENTRYPOINT ["unblob"]
