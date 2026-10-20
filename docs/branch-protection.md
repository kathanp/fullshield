# Branch protection

A person with admin access sets these required status checks on `main`. This file only lists the names. It does not change repository settings.

The names come from the six-job matrix in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). The job name is `verify (${{ matrix.os }}, node ${{ matrix.node }})` with `os` of `ubuntu-24.04`, `macos-latest`, and `windows-latest`, and `node` of `22` and `24`.

Required status checks:

- `verify (ubuntu-24.04, node 22)`
- `verify (ubuntu-24.04, node 24)`
- `verify (macos-latest, node 22)`
- `verify (macos-latest, node 24)`
- `verify (windows-latest, node 22)`
- `verify (windows-latest, node 24)`

`bench` uses `continue-on-error` and is not one of these six.

How to run other scanners beside FullShield is in [use-with-other-tools.md](use-with-other-tools.md).
