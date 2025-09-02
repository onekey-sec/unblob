#/bin/sh -xeu

apt-get update

apt-get install --no-install-recommends -y \
    android-sdk-libsparse-utils \
    curl \
    e2fsprogs \
    erofs-utils \
    lz4 \
    lziprecover \
    lzop \
    p7zip-full \
    partclone \
    unar \
    upx \
    xz-utils \
    libmagic1 \
    zstd

curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_$(dpkg --print-architecture).deb"
dpkg -i sasquatch_1.0.deb
rm -f sasquatch_1.0.deb
