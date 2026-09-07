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

  # Dependencies of the Apple Encrypted Archive handler that are not packaged in
  # nixpkgs yet.
  pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
    (python-final: _python-prev: {
      pyliblzfse = python-final.buildPythonPackage rec {
        pname = "pyliblzfse";
        version = "0.4.1";
        pyproject = true;

        src = python-final.fetchPypi {
          inherit pname version;
          sha256 = "bb0b899b3830c02fdf3dbde48ea59611833f366fef836e5c32cf8145134b7d3d";
        };

        build-system = [ python-final.setuptools ];

        pythonImportsCheck = [ "liblzfse" ];

        meta = {
          description = "Python bindings for the LZFSE reference implementation";
          homepage = "https://github.com/ydkhatri/pyliblzfse";
          license = final.lib.licenses.mit;
        };
      };

      pyhpke = python-final.buildPythonPackage rec {
        pname = "pyhpke";
        version = "0.6.5";
        pyproject = true;

        src = python-final.fetchPypi {
          inherit pname version;
          sha256 = "8dac22eb143cd83b8066213b8ad0ecc9d5326ef41f930197197f3bbb5c99cb93";
        };

        build-system = [ python-final.uv-build ];

        dependencies = [ python-final.cryptography ];

        pythonImportsCheck = [ "pyhpke" ];

        meta = {
          description = "Hybrid Public Key Encryption (RFC9180) implementation";
          homepage = "https://github.com/dajiaji/pyhpke";
          license = final.lib.licenses.mit;
        };
      };

      python-aea = python-final.buildPythonPackage rec {
        pname = "python_aea";
        version = "1.1.0";
        pyproject = true;

        src = python-final.fetchPypi {
          inherit pname version;
          sha256 = "ee9b5b61456f4bd3c20dc39f6b5fc3f262f4de3a76c3d2fd42617be5ff1153ed";
        };

        build-system = [ python-final.setuptools ];

        dependencies = with python-final; [
          cryptography
          lz4
          pyliblzfse
        ];

        pythonImportsCheck = [ "aea" ];

        meta = {
          description = "Apple Encrypted Archive (AEA) reader";
          homepage = "https://pypi.org/project/python-aea/";
          license = final.lib.licenses.mit;
        };
      };
    })
  ];

  unblob = final.callPackage ./package.nix { };
}
