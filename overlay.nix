final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  sevenzip =
    let
      inherit (final) _7zz;
      _7z-link = final.runCommand "_7z-link" { } ''
        mkdir -p $out/bin
        ln -sfn ${_7zz}/bin/7zz "$out/bin/7z"
      '';
    in
    final.symlinkJoin {
      name = "sevenzip";
      paths = [
        _7zz
        _7z-link
      ];
    };

  erofs-utils = prev.erofs-utils.overrideAttrs (_: rec {
    version = "1.8.10";
    src = final.fetchFromGitHub {
      owner = "erofs";
      repo = "erofs-utils";
      rev = "v${version}";
      sha256 = "1qlig9q1fdjl0zn7206dbv7w5ssjg4az4hg7y3vk69ly0zbmwkil";
    };
  });

  unblob = final.callPackage ./package.nix { };
}
