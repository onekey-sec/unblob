final: prev:

{
  # https://github.com/tytso/e2fsprogs/issues/152
  e2fsprogs-nofortify = prev.e2fsprogs.overrideAttrs (super: {
    pname = "e2fsprogs-nofortify";
    hardeningDisable = (super.hardeningDisable or [ ]) ++ [ "fortify3" ];
    nativeCheckInputs = (super.nativeCheckInputs or [ ]) ++ [ final.which ];
  });

  unblob = final.callPackage ./package.nix { };
}
