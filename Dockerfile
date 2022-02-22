FROM python:3.8-slim

RUN mkdir -p /data/input /data/output
RUN useradd -m unblob
RUN chown -R unblob /data

WORKDIR /data/output

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl \
    e2fsprogs \
    gcc \
    g++ \
    git \
    img2simg \
    liblzo2-dev \
    liblz4-dev \
    liblzma-dev \
    libzstd-dev \
    lz4 \
    lziprecover \
    lzop \
    make \
    unar \
    xz-utils \
    zlib1g-dev
RUN curl -s https://www.7-zip.org/a/7z2107-linux-x64.tar.xz --output - \
    | tar -C /usr/local/bin --transform 's/7zzs/7z/' -Jxvf - 7zzs
RUN git clone https://github.com/IoT-Inspector/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch/squashfs-tools \
    && make \
    && make install

USER unblob
ENV PATH="/home/unblob/.local/bin:${PATH}"

# You MUST do a poetry build before to have the wheel to copy & install here (CI action will do this when building)
COPY dist/*.whl /tmp/
RUN pip --disable-pip-version-check install --upgrade pip
RUN pip install /tmp/unblob*.whl

ENTRYPOINT ["unblob"]
