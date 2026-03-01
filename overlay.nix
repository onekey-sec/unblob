final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  sevenzip = final.stdenvNoCC.mkDerivation rec {
    pname = "sevenzip";
    version = "26.00";

    src =
      let
        baseUrl = "https://www.7-zip.org/a";
        versionNoDots = final.lib.replaceStrings [ "." ] [ "" ] version;
        sources = {
          x86_64-linux = {
            url = "${baseUrl}/7z${versionNoDots}-linux-x64.tar.xz";
            sha256 = "sha256-x03EpISSzeQ/X+wQ1T+ypm9SDkpipp1jDETLIsR37cY=";
          };
          aarch64-linux = {
            url = "${baseUrl}/7z${versionNoDots}-linux-arm64.tar.xz";
            sha256 = "sha256-qo89ChmvlnTTrw7HiLTiYVAQceYmzXWtFJ8cLBdsyH0=";
          };
          x86_64-darwin = {
            url = "${baseUrl}/7z${versionNoDots}-mac.tar.xz";
            sha256 = "sha256-ii6nNLUrLLfVaPXxPgoTe+owBLIhvb7lMZdyipBRyEk=";
          };
          aarch64-darwin = {
            url = "${baseUrl}/7z${versionNoDots}-mac.tar.xz";
            sha256 = "sha256-ii6nNLUrLLfVaPXxPgoTe+owBLIhvb7lMZdyipBRyEk=";
          };
        };
      in
      final.fetchurl sources."${final.stdenv.targetPlatform.system}";

    sourceRoot = ".";
    dontConfigure = true;
    dontBuild = true;

    nativeBuildInputs = final.lib.optionals final.stdenvNoCC.isLinux [
      final.autoPatchelfHook
    ];

    buildInputs = final.lib.optionals final.stdenvNoCC.isLinux [
      final.stdenv.cc.cc.lib
    ];

    installPhase = ''
      runHook preInstall

      mkdir -p "$out/bin" "$out/share/doc/7zip"
      install -m755 7zz "$out/bin/"
      if [ -f 7zzs ]; then
        install -m755 7zzs "$out/bin/"
      fi
      ln -s 7zz "$out/bin/7z"

      install -m644 License.txt readme.txt History.txt "$out/share/doc/7zip/"

      runHook postInstall
    '';

    meta = {
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  };

  unblob = final.callPackage ./package.nix { };
}
