final: prev:

{
  inherit (final.python3.pkgs) unblob;
  _sources = final.callPackage ./nix/_sources/generated.nix { };

  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs
    (super: {
      pname = "e2fsprogs-nofortify";
      hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
      nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
    });

  # Own package updated independently of nixpkgs
  jefferson = final.callPackage ./nix/jefferson { };

  lief = prev.lief.overrideAttrs (super: with final; {

    outputs = [ "out" "py" ];

    nativeBuildInputs = [
      cmake
      ninja
    ];

    # Not a propagatedBuildInput because only the $py output needs it; $out is
    # just the library itself (e.g. C/C++ headers).
    buildInputs = with python3.pkgs; [
      python3
      setuptools
      tomli
    ];

    env.CXXFLAGS = toString (lib.optional stdenv.isLinux [ "-ffunction-sections" "-fdata-sections" "-fvisibility-inlines-hidden" "-static-libstdc++" "-static-libgcc" ]
      ++ lib.optional stdenv.isDarwin [ "-faligned-allocation" "-fno-aligned-new" "-fvisibility=hidden" ]);

    env.CFLAGS = toString (lib.optional stdenv.isLinux [ "-ffunction-sections" "-fdata-sections" "-static-libstdc++" "-static-libgcc" ]);
    env.LDFLAGS = toString (lib.optional stdenv.isLinux [ "-Wl,--gc-sections" "-Wl,--exclude-libs,ALL" ]);


    dontUseCmakeConfigure = true;

    buildPhase = ''
      runHook preBuild

      mkdir -p build
      cmake -S . -B build -GNinja -DCMAKE_LINK_WHAT_YOU_USE=on -DBUILD_SHARED_LIBS=on -DLIEF_INSTALL_COMPILED_EXAMPLES=off -DCMAKE_INSTALL_PREFIX=$out -DCMAKE_BUILD_TYPE=Release

      cmake --build build --target all

      runHook postBuild
    '';

    postBuild = ''
      pushd api/python
      ${python3.interpreter} setup.py build --parallel=$NIX_BUILD_CORES
      popd
    '';

    installPhase = ''
      runHook preInstall

      cmake --build build --target install

      runHook postInstall
    '';

    postInstall = ''
      pushd api/python
      ${python3.interpreter} setup.py install --skip-build --root=/ --prefix=$py
      popd
    '';

  });

  pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
    (python-final: python-prev: {
      # Missing from nixpkgs
      treelib = python-final.callPackage ./nix/treelib { };

      # Missing from nixpkgs
      pyfatfs = python-final.callPackage ./nix/pyfatfs { };

      # The reason for everything
      unblob = python-final.callPackage ./nix/unblob { };
    })
  ];

  # Own package updated independently of nixpkgs
  ubi_reader = final.callPackage ./nix/ubi_reader { };
}
