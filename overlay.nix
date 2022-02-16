final: prev:

{
  unblob = prev.callPackage ./. { };
  gnustep = prev.callPackage ./nix/gnustep { inherit (prev) gnustep; };
}
