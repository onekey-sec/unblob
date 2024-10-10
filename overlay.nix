final: prev:

{
  inherit (final.python3.pkgs) unblob;
  _sources = final.callPackage ./nix/_sources/generated.nix { };

  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  simg2img = prev.simg2img.overrideAttrs (super: {
    postPatch = ''
      substituteInPlace output_file.cpp \
        --replace-fail \
        'aligned_offset = offset & ~(4096 - 1);' \
        'aligned_offset = offset & ~(sysconf(_SC_PAGESIZE) - 1);'
    '';
  });

  # Own package updated independently of nixpkgs
  jefferson = final.callPackage ./nix/jefferson { };

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
