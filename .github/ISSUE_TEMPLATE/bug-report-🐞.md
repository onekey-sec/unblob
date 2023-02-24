---
name: "Bug Report \U0001F41E"
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

<!--
  To make it easier for us to help you, please include as much useful information as possible.

  Before opening a new issue, please search existing issues https://github.com/onekey-sec/unblob/issues
-->

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Launch unblob with command `unblob --specific --flag filename`
2. Go to extraction directory
4. See error

<!-- You can either share the error logs in the section below or upload a gist and share the link below. -->

<details>
<summary>Error details</summary>

<!-- Paste error details in the section between the backticks below: -->
```

```

</details>

<!--
In order for us to investigate, you MUST attach a binary sample to this issue.

Make sure you're not sharing samples that are protected by NDAs or contain sensitive
information.
 -->

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment information (please complete the following information):**
 - OS: [e.g. Ubuntu Linux]
 - Software versions (Docker, Python, Nix, Poetry, if applicable)

We recommend you execute and paste the results of those commands in this issue so we can get a sense of your environment:

- Linux/Darwin kernel version with `uname -avr`
- Linux distribution with `cat /etc/lsb-release`
- MacOS distribution with `sw_vers`
- Poetry version with `poetry env info`
- Nix install info with `nix flake info`
- Pip install info `pip freeze`
- Unblob dependencies info with `unblob --show-external-dependencies`

**Additional context**
Add any other context about the problem here.
