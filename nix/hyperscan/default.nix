{ lib, stdenv, buildPythonPackage, fetchPypi, hyperscan, pkg-config, poetry, pcre }:

let
  pcre-src = stdenv.mkDerivation {
    inherit (pcre) src name version;
    phases = [ "unpackPhase" "patchPhase" "installPhase" ];
    patchPhase = ''
      substituteInPlace config.h.generic \
        --replace '".libs/"' 'PREFIX'
    '';
    installPhase = "mv $PWD $out";
  };
  hyperscan-with-chimera = hyperscan.overrideAttrs (super: {
    outputs = super.outputs ++ [ "pcre" ];

    postPatch = super.postPatch + ''
      # hscollider doesn't compile on glibc-2.34 https://github.com/intel/hyperscan/issues/359
      sed -i '1i return()' tools/hscollider/CMakeLists.txt
    '';

    cmakeFlags = super.cmakeFlags ++ [
      "-DFAT_RUNTIME=ON"
      "-DBUILD_AVX512=ON"
      "-DBUILD_SHARED_LIBS=OFF"
      "-DBUILD_STATIC_AND_SHARED=OFF"
      "-DPCRE_SOURCE=${pcre-src}"
    ];

    nativeBuildInputs = super.nativeBuildInputs ++ [ pkg-config ];
    postInstall = "install -Dt $pcre/lib lib/libpcre.a";
  });
in
buildPythonPackage rec {
  pname = "hyperscan";
  version = "0.3.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-jaz1uDnPsxAEruB88/PgxX4Np9xEReLnCuqzJQhjeW8";
  };

  preBuild = "find ${hyperscan-with-chimera}";
  PCRE_PATH = "${hyperscan-with-chimera.pcre}/lib";

  format = "pyproject";

  buildInputs = [ poetry hyperscan-with-chimera ];
  nativeBuildInputs = [ pkg-config ];
}
