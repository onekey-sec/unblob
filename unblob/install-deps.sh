#/bin/sh -xeu

apt-get update

apt-get install --no-install-recommends -y \
    android-sdk-libsparse-utils \
    curl \
    lz4 \
    lziprecover \
    lzop \
    p7zip-full \
    unar \
    xz-utils \
    libmagic1 \
    zstd

curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_$(dpkg --print-architecture).deb"
dpkg -i sasquatch_1.0.deb
rm -f sasquatch_1.0.deb

curl -L -o libext2fs2_1.47.0-3.ok1.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok1/libext2fs2_1.47.0-3.ok1_$(dpkg --print-architecture).deb"
dpkg -i libext2fs2_1.47.0-3.ok1.deb
rm -f libext2fs2_1.47.0-3.ok1.deb

curl -L -o e2fsprogs_1.47.0-3.ok1.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok1/e2fsprogs_1.47.0-3.ok1_$(dpkg --print-architecture).deb"
dpkg -i e2fsprogs_1.47.0-3.ok1.deb
rm -f e2fsprogs_1.47.0-3.ok1.deb
