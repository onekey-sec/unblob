FROM python:3.8-slim

RUN mkdir -p /data/input /data/output
RUN useradd -m unblob
RUN chown -R unblob /data

WORKDIR /data/output

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    e2fsprogs \
    gcc \
    git \
    img2simg \
    liblzo2-dev \
    lz4 \
    lziprecover \
    lzop \
    p7zip-full \
    unar \
    xz-utils \
    zlib1g-dev \
    libmagic1 \
    libhyperscan5 \
    zstd
RUN curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v1.0/sasquatch_1.0_amd64.deb \
    && dpkg -i sasquatch_1.0_amd64.deb \
    && rm -f sasquatch_1.0_amd64.deb

USER unblob
ENV PATH="/home/unblob/.local/bin:${PATH}"

# You MUST do a poetry build before to have the wheel to copy & install here (CI action will do this when building)
COPY dist/*.whl /tmp/
RUN pip --disable-pip-version-check install --upgrade pip
RUN pip install /tmp/unblob*.whl

ENTRYPOINT ["unblob"]
