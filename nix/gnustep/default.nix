{ lib, gnustep, icu, binutils-unwrapped, libiconv }:

{
  base = gnustep.base.overrideAttrs (_: {
    preFixup = ''
      # these files would pull in an insane amount of build dependencies
      rm -rf $out/share/{GNUstep,.GNUstep.conf}
    '';

    # Pass in the minimal amount of dependencies
    propagatedBuildInputs = [ gnustep.libobjc icu binutils-unwrapped ];

    configureFlags = [
      "--disable-invocations"
      "--disable-tls"
      "--disable-xml"
    ];
  });
  inherit (gnustep) make;
}
