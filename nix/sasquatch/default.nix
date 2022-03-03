{ src, lib, squashfsTools }:

let
  self = squashfsTools.overrideAttrs (_: {
    pname = "sasquatch";
    inherit src;
    patches = [ ]; # Patches are already applied to input

    passthru.bigEndian = self.overrideAttrs (super: {
      pname = "${super.pname}-be";
      preConfigure = (super.preConfigure or "") + ''
        export CFLAGS="-DFIX_BE"
      '';
      postInstall = (super.postInstall or "") + ''
        mv $out/bin/sasquatch{,-v4be}
      '';
    });
  });
in
self
