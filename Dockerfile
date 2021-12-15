FROM python:3.8-slim

RUN mkdir -p /data/input /data/output
RUN useradd unblob

ENTRYPOINT ["unblob"]

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


# You MUST do a poetry build before to have the wheel to copy & install here (CI action will do this when building)
COPY dist/*.whl /tmp/
RUN pip install /tmp/unblob*.whl

WORKDIR /data/output
RUN chown -R unblob /data
USER unblob
