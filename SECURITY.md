# Security policy

## What this project will not hold

PLIMSOLL must never receive, store, or transmit a user's dataset, model,
prompts, or outputs. Reports that we have done so are treated as a
critical incident, not as a feature request.

A sealed decision rule must not be overridable by a flag, environment
variable, setting, or paid tier. A patch that introduces such a path is
a vulnerability.

Verification must remain possible without our log as the only endpoint.

## Reporting a vulnerability

Please report security issues to developwith.gt@gmail.com.

Do not open a public GitHub issue for a vulnerability.

Include:

- A description of the issue and its impact
- Steps to reproduce, or a proof of concept, if you have one
- Affected commits or release tags, if known

We will acknowledge receipt as soon as we can and keep you informed of
progress toward a fix.

## Supported versions

This repository is pre-release. Until a tagged release exists, report
against the default branch.
