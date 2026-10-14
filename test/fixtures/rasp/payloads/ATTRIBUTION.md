# PayloadsAllTheThings attribution

These files are **payload lists only**. They are local RASP test fixtures.
FullShield does **not** execute them against any system.

## Source

- Project: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Author / copyright: Swissky (c) 2019
- License: MIT (full text below)
- Downloaded: 2026-10-14
- Method: `curl` of raw GitHub files from branch `master`

There is no `Server Side Request Forgery/Intruder/ssrf.txt` in the repo
(404). Closest existing sources are the SSRF markdown notes, from which
URL-shaped payloads are extracted when building `attack-corpus.json`.

## Files vendored (original names)

| Local path | Upstream path |
|---|---|
| `sqli/Auth_Bypass.txt` | `SQL Injection/Intruder/Auth_Bypass.txt` |
| `sqli/Auth_Bypass2.txt` | `SQL Injection/Intruder/Auth_Bypass2.txt` |
| `sqli/Generic_ErrorBased.txt` | `SQL Injection/Intruder/Generic_ErrorBased.txt` |
| `cmdi/command-execution-unix.txt` | `Command Injection/Intruder/command-execution-unix.txt` |
| `cmdi/command_exec.txt` | `Command Injection/Intruder/command_exec.txt` |
| `path/directory_traversal.txt` | `Directory Traversal/Intruder/directory_traversal.txt` |
| `path/deep_traversal.txt` | `Directory Traversal/Intruder/deep_traversal.txt` |
| `ssrf/README.md` | `Server Side Request Forgery/README.md` |
| `ssrf/SSRF-Cloud-Instances.md` | `Server Side Request Forgery/SSRF-Cloud-Instances.md` |
| `LICENSE` | `LICENSE` |

## MIT License

MIT License

Copyright (c) 2019 Swissky

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
