# Ground-truth review

Every `bench/*/ground-truth.json` stays `"reviewed": false` until a human flips it. Do not cite recall from these files.

For each entry:

1. Open the `source` link. It must be that app's own documentation at the pinned commit.
2. The file in the entry exists at that commit and the described code is on the recorded line, or within the surrounding few lines if the doc does not number lines.
3. The `class` is one FullShield claims (`sqli`, `nosqli`, `cmdi`, `path`, `xss`, `ssrf`, `redirect`, `eval`, `jwt`, `crypto`, `proto`, `secrets`, `deps`, `config`) or the entry is `inScope: false` with a one-line reason.
4. Matching for a later score is class + file + line ±3. Moving a finding's line is not a recall gain.

Untouched apps (`verademo-javascript`, `serverless-goat`, `mongection`) have not been scanned. Do not scan them to tune a rule.
