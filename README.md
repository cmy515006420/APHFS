# APHFS

This is the public version 1.0.0 repository for **All-Possibility Hierarchical
Filtering Simulation (APHFS)**:

https://github.com/cmy515006420/APHFS

Mingyuan Chen conceived the central APHFS theory and research direction. The
reported study is a complete evaluation of the declared 256-rule elementary
cellular-automaton grammar under a fixed observation and accounting interface.
It tests the framework's finite-grammar search, terminal accounting,
observational ambiguity, model-class inadequacy, fidelity, and decision
machinery. It is not physical, biological, aging, rejuvenation, or therapeutic
validation.

## Public contents

The repository includes the final manuscript and Supplement, executable source
code, fixed configurations and schemas, environment locks, safe aggregate
source tables, figure-generation code, A0 candidate/signature records, and
read-only reconstruction and validation tools. It contains no raw calibration
or locked role values, protected result container, private authorization
record, or credential. It cannot replay the one-time protected evaluation and
is not an independently written implementation, a new-role replication, or
validation on new data.

Immutable identity anchors:

- locked result SHA-256: `6fb3f08e48b4d3496e190fbc38b029ee7c15e327c504924f8c03b6e2083aec9c`
- locked execution receipt SHA-256: `730bfe099a74b1ccfa281e653e9330bf91a5e73c30b24a58cf52dd88028c4766`

PDF and SVG figures are canonical byte-reproducible figure outputs. PNG files
are renderer-dependent convenience previews; their integrity, dimensions, and
same-renderer parity—not cross-renderer byte identity—form the public contract.

## Data and code availability

The accompanying Supplement and reproducibility archive provide the executable
source tree, fixed configurations and schemas, environment locks, safe
aggregate source tables, figure-generation code, A0 candidate/signature
records, and read-only tools for reconstructing reported endpoint counts,
exact-binomial calculations, aggregate tables, figures, intervals, and costs.
The same versioned materials are available in this public repository at
https://github.com/cmy515006420/APHFS. The archive and repository do not include raw calibration or
locked role values or the protected result container; they do not rerun the
original one-time evaluation and are not an independently written
implementation, new-role replication, or validation on new data.

## Validation and release-only figure test

Run the standard-library validator on a fresh ZIP extraction or clean
`git archive` export (not directly on a clone containing `.git`):

```bash
python3 -I -B tools/validate_public_repository_v1.py --path .
```

The Figure 3 test reads only released aggregate tables. It cannot run a
benchmark, calibration, locked audit, role replay, or materialization. The PNG
preview portion requires a local `pdftoppm`; PDF text inspection uses the
locked `pypdf` dependency.

```bash
python3.12 -m venv ../aphfs-release-test
../aphfs-release-test/bin/python -m pip install -r requirements-release-v2_5.txt
../aphfs-release-test/bin/python -m pytest -q -s tests/release/test_figure3_evidence_sync_v3_8.py
```

## Licenses and AI assistance

Software is released under the MIT License. The manuscript, documentation,
figures, and released aggregate/source data are licensed under CC BY 4.0. The
bundled Liberation Sans fonts remain under SIL OFL 1.1. See
`LICENSES/LICENSE_MAPPING.md`.

The manuscript separately discloses substantive use of OpenAI ChatGPT and
Codex and Anthropic Claude, with limited exploratory critique from Gemini and
Grok. AI outputs were treated as provisional suggestions rather than evidence
or independent validation. Mingyuan Chen made the final scientific decisions
and accepts responsibility within the disclosed review scope.
