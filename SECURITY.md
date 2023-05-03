# Security Policy

## Reporting
As a security company, ONEKEY commits to all of its open source products having sound and secure implementations.

All security bugs in ONEKEY products should be reported by email to security@onekey.com. We strongly suggest that you encrypt your email content using our PGP public key (see below). Security bugs must not  be reported through public Github issues.

In accordance with the [Responsible Full Disclosure Policy (RFPolicy) v2.0](https://dl.packetstormsecurity.net/papers/general/rfpolicy-2.0.txt), your email will be acknowledged within five days. The security team will then keep you informed of the progress being made towards a fix and full announcement at least every five days.

## Disclosure policy
ONEKEY has a 5 step disclosure process.

1. The security report is received and is assigned a primary handler. This person will coordinate the fix and release process.

1. The problem is confirmed and a list of all affected versions is determined.

1. Code is audited to find any potential similar problems.

1. Fixes are prepared and applied to the latest version. These fixes are not committed to the public repository but rather held locally pending the announcement.

1. On the embargo date, the advisory is pushed to the affected repository’s wiki, the changes are pushed to the public repository and new builds are deployed to package repositories. A copy of the advisory is then published in the release notes.

This process can take some time, especially when coordination is required with maintainers of other projects. Every effort will be made to handle the bug in an as timely a manner as possible, however it’s important that we follow the release process above to ensure that the disclosure is handled in a consistent manner.

We will never push silent fixes of reported security issues to our code bases. Our security fixes commit will always contain explicit commit messages describing the issue and fix in details and reference a CVE if applicable. Our security advisories will always credit the reporter either by name, handle, or email address. If the reporter wishes to stay anonymous, we will credit them as “anonymous researcher”.

## PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGJWa+gBCADwVEuade39t7qC2L997zAbHg5MvmqgL/mgAz0wc+SnB60lKP1S
ALAedVVs68ODrNIy5Ob542oXvKVaiAGPDjpD76TTHUaONKCtAWQMjd1FG/zi7U7F
wtzON22xc9pOlbf7Vind1bV6eF8rSRt8xIvhYIs6wl6cqHOAqMfOzQp/FqA9LVkd
KZwHTwcIeXm2simpNk6GkjVVjy6QRc3tO0KpLyfUGNLrUBhA9tNtzjbZ5nUESIuE
FNgCai0pX89h8PuXiRABDQq4SVxq9+Wl3xkdX0gck444fQLLRxpYVpl4mBodY79/
Hl1MuYFzm4xgBHD5LEeZ9wgqFSRlklXGI+URABEBAAG0GnJlc2VhcmNoQGlvdC1p
bnNwZWN0b3IuY29tiQFOBBMBCAA4FiEE7X8jOwd94T3HaMCoSogMvqTieacFAmJW
a+gCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQSogMvqTieaePPAf/XRO3
SZppFI+d9FLwzL4in8dMFAsGWOS+HzifCisNJ4ERHyyD1UK1ZlS0FyXfoylUIINl
62MjzGVrUj6p6i3qTuOjymOJYhR3I3CKLGUh5JA+DPQxJ9+kHTQbUpxvXJQ8P2BS
x3Cz11zu9EDMzEC2hbchANhJ8pUnQhAeuSbAwAxzGEvXqwm789IvuXFkGZkAR60J
eQnbvgT1Ij2Awq7oOBmOEQ79MzvB7m+Bd8uQQCOxqNCX+2TTH+PKC/2x0RwlyYG9
yjnUyyPttyCc8dkjUiirchhE9g5kYCUNmprWw7Pr5pO+5Wuwk+1DwYGXie81aJkZ
jWqTE90EvmMbatGf4LkBDQRiVmvoAQgA0d546TrhcBPh3nbiE++kFz+Pne9fdorv
3ln2zMmFxtn6f4eNdwPlnu1vyTqTr0F/Sb39FU1t7c1UHfxbqvYHfExEKjI9Vzzy
74/rRK2RCO1PoUM4X+ngy13V4FH0EZNy0srXHZsD2TqWLCtsA34k87wBUizFaFUa
tI1Dg8ambo9i/7flovC1y3oX/hK+Ct6ey5r/SZ0gZ4esZSRb8ogddumZRFcakR6o
Vz91rHjAvvE4bxC1ioCiX0YXhst/GawwshZeq26Ju96QZQ/kSb4vwGQ1ThtSEsD4
rypZopdv4U+JqwBlLpsL71iF+/wiEXIgja1zQc06cI9YMPKcAZSA+QARAQABiQE2
BBgBCAAgFiEE7X8jOwd94T3HaMCoSogMvqTieacFAmJWa+gCGwwACgkQSogMvqTi
eaf7qwgAwN20J6wCUZmBD/sh27fmmpmsKGi86S8dN8Dt6QP9et5L9yMwGuxUuiLU
SByuBVCs6MvJGtyg5r1ZUbzevb3Ge7I4PPWGqnSiydxgCo8psmM7T2vpruKayfCb
FkYlwaoTAR9vD4rmftJO+X0fxwOvNtS6Xv4JNugUfeSEk4hIm5GPabSBWFd4imfy
QnTDT/JvV/HOf6LC1Nonz9aiwr6+F6MXQihZKGiK/tDoWrB5404p6JToLpeFcVaT
vylQcgCz/sFGLc4uV7XEobCDZpfP5UC+hjXpIorrTmKMSLotq8s5vx84W3qeZzgt
Gh7fzoVy9KKksJH0j1eFpBa+FgJM8g==
=obzE
-----END PGP PUBLIC KEY BLOCK-----
```
