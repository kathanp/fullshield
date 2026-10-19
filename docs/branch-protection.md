# Branch protection

A human sets these required checks on `main`. Cursor does not change repository settings.

The pull-request matrix job is named `verify (${{ matrix.os }}, node ${{ matrix.node }})`. The six required check names are:

- `verify (ubuntu-24.04, node 22)`
- `verify (ubuntu-24.04, node 24)`
- `verify (macos-latest, node 22)`
- `verify (macos-latest, node 24)`
- `verify (windows-latest, node 22)`
- `verify (windows-latest, node 24)`

Push to `next` uses one job: `verify (ubuntu-24.04, node 24)`. That job is not one of the six `main` checks.
