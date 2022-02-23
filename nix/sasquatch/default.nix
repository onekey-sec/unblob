{ src, squashfsTools }:

squashfsTools.overrideAttrs (super: {
  inherit src;
  patches = [ ]; # Patches are already applied to input
})
