{ yara }:

yara.overrideAttrs (super: {
  patches = [
    ./0001-Replace-yr_re_fast_exec-with-a-faster-implementation.patch
    ./0001-Fix-yr_re_fast_exec-on-larger-than-2GiB-files.patch
    ./0002-Use-YR_RE_SCAN_LIMIT-as-limit-instead-of-MAX_INT.patch
  ];
})
