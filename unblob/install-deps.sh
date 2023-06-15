#/bin/sh -xeu

apt-get update

apt-get install --no-install-recommends -y \
    android-sdk-libsparse-utils \
    curl \
    e2fsprogs \
    gcc \
    git \
    liblzo2-dev \
    lz4 \
    lziprecover \
    lzop \
    p7zip-full \
    unar \
    xz-utils \
    zlib1g-dev \
    libmagic1 \
    zstd

curl -L -o sasquatch_1.0_amd64.deb https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_amd64.deb
dpkg -i sasquatch_1.0_amd64.deb
rm -f sasquatch_1.0_amd64.deb
