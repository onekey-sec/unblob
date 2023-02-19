inputs: final: prev:

{
  unblob = prev.callPackage ./. { };
  sasquatch = prev.callPackage ./nix/sasquatch { inherit (prev) squashfsTools; src = inputs.sasquatch; };
  mkPoetryApp = prev.callPackage ./nix/poetry { };
}
