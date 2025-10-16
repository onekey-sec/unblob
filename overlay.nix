final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  p7zip16 = prev.p7zip.overrideAttrs (super: rec {
    pname = "p7zip16";
    version = "16.02";
    srcs = [
      (final.fetchurl {
        url = "mirror://sourceforge/p7zip/p7zip_${version}_src_all.tar.bz2";
        sha256 = "5eb20ac0e2944f6cb9c2d51dd6c4518941c185347d4089ea89087ffdd6e2341f";
      })
      (final.fetchurl {
        url = "http://deb.debian.org/debian/pool/main/p/p7zip/p7zip_${version}+dfsg-8.debian.tar.xz";
        sha256 = "sha256-ASF9yhZnrw3kiTWlHcRqrUQubryseZ1xQQG37fllHrU=";
      })
    ];
    sourceRoot = "p7zip_${version}";
    nativeBuildInputs = (super.nativeBuildInputs or [ ]) ++ [ final.quilt ];
    prePatch = ''
      export QUILT_PATCHES=../debian/patches
      quilt push -a
    '';
    # orig had `src` attribute, but we are using `srcs`. This trips a warning.
    __intentionallyOverridingVersion = true;

    separateDebugInfo = true;
  });

  unblob = final.callPackage ./package.nix { };
}
