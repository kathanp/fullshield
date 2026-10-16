# SUPPLY-WORKFLOW-001

**Dependency writes GitHub workflows, git hooks, or CI config (static).** CWE-829.

Experimental (`FULLSHIELD_EXPERIMENTAL_VEX=1`). Flags install scripts or package code that write `.github/`, `.git/hooks/`, or CI config files. Critical. Never executes packages.

## Remediation

Do not install the package until the write is reviewed. Prefer `--ignore-scripts` and pin CI config so dependencies cannot persist a workflow.
