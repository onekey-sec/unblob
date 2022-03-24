inputs: final: prev:

{
  unblob = prev.callPackage ./. { };
  gnustep = prev.callPackage ./nix/gnustep { inherit (prev) gnustep; };
  sasquatch = prev.callPackage ./nix/sasquatch { inherit (prev) squashfsTools; src = inputs.sasquatch; };
  mkPoetryApp = prev.callPackage ./nix/poetry { };
}
