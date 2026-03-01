#/bin/sh -xeu

apt-get update

apt-get install --no-install-recommends -y \
    android-sdk-libsparse-utils \
    curl \
    erofs-utils \
    lz4 \
    lziprecover \
    lzop \
    partclone \
    unar \
    upx \
    xz-utils \
    libmagic1 \
    zstd

case "$(dpkg --print-architecture)" in
    amd64) sevenzip_arch="x64" ;;
    arm64) sevenzip_arch="arm64" ;;
    *)
        echo "Unsupported architecture for 7-Zip: $(dpkg --print-architecture)" >&2
        exit 1
        ;;
esac

curl -L -o 7zip.tar.xz "https://www.7-zip.org/a/7z2600-linux-${sevenzip_arch}.tar.xz"
install -d /usr/local/bin
tar -xf 7zip.tar.xz -C /usr/local/bin 7zz 7zzs
ln -sf /usr/local/bin/7zz /usr/local/bin/7z
rm -f 7zip.tar.xz

curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-6/sasquatch_1.0_$(dpkg --print-architecture).deb"
dpkg -i sasquatch_1.0.deb
rm -f sasquatch_1.0.deb

curl -L -o libext2fs2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
curl -L -o e2fsprogs_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
curl -L -o libss2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
dpkg -i libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb
dpkg -i e2fsprogs_1.47.0-3.ok2.deb
rm -f libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb e2fsprogs_1.47.0-3.ok2.deb
