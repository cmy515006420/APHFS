# APHFS local public-release candidate v3

Status: local pre-publication candidate. No Git remote, repository URL, DOI,
push, or external upload is represented by this archive.

The central APHFS theory and research direction were conceived by Mingyuan
Chen. The current 256-rule elementary-cellular-automaton study is an enumerable
test of the framework's search, accounting, ambiguity, inadequacy, fidelity,
and decision machinery; it is not a physical, biological, aging, rejuvenation,
or therapeutic validation.

Immutable identity anchors:

- locked result SHA-256: `6fb3f08e48b4d3496e190fbc38b029ee7c15e327c504924f8c03b6e2083aec9c`
- locked receipt SHA-256: `730bfe099a74b1ccfa281e653e9330bf91a5e73c30b24a58cf52dd88028c4766`

This candidate contains the executable source tree, fixed public
configurations and schemas, environment locks, safe aggregate source tables,
figure-generation code, A0 accounting/signature evidence through the finite
grammar and released audit ledger, and a read-only audit tool. It deliberately
contains no raw role values or protected result container. It cannot replay the
one-time evaluation and is not an independently written implementation,
new-role replication, or validation on new data.

PDF and SVG figures are canonical byte-reproducible outputs. PNG files are
renderer-dependent convenience previews; their integrity and dimensions, not
cross-renderer byte identity, are the public contract.

Code is licensed under MIT. The manuscript, documentation, figures, and
released aggregate data use CC BY 4.0. See `LICENSES/LICENSE_MAPPING.md`.

## Data and Code Availability

The accompanying Supplement and versioned reproducibility archive provide the executable source tree, fixed configurations and schemas, environment locks, safe aggregate source tables, figure-generation code, A0 candidate/signature records, and read-only tools for reconstructing reported endpoint counts, exact-binomial calculations, aggregate tables, figures, intervals, and costs. The archive does not rerun the original one-time evaluation and is not an independently written implementation, new-role replication, or validation on new data. Code is licensed under the MIT License; the manuscript, documentation, and released aggregate data use CC BY 4.0. A public repository URL will be added only after the author separately authorizes publication and verifies the final remote contents.

## AI-assisted technologies

The author used OpenAI ChatGPT (primarily GPT-5.6 Sol through the standard and reasoning settings available in the author's account) and OpenAI Codex for outlining and drafting, methodological and formal suggestions, software implementation and refactoring, tests, mathematical exposition, figure preparation, literature organization, adversarial review, release engineering, and editing. Anthropic Claude (primarily Claude Opus 5 and Claude Fable 5.1) was used for methodological critique, adversarial review, and revision suggestions. Google Gemini and xAI Grok were used only for limited exploratory critique; their exact versions were not recorded, and no specific retained substantive contribution is attributed to them. The model-version history is therefore partial. AI outputs were treated as provisional suggestions, not evidence or independent validation. Mingyuan Chen originated the central research direction, set the scientific questions and claim boundaries, reviewed the manuscript and reported results, checked the functions and assumptions of Equations (1)--(10), the Clopper--Pearson calculations, relevant portions of load-bearing sources, and reported file-integrity checks, and directly observed the public read-only aggregate recomputation. The author has functional-level understanding of the core scientific code but did not conduct a repository-wide line-by-line review. The author made the final scientific decisions and accepts responsibility for the work within this disclosed review scope. No human, animal, clinical, or identifiable private biological data were supplied to these systems. AI systems are not authors or CRediT contributors.

Validate a fresh extraction without importing APHFS:

```bash
python3 -I -B tools/validate_v37_release_packages.py --kind github --path .
```

The release-only Figure 3 reproducibility check reads safe aggregate tables;
it does not open protected results or raw roles and does not execute a
benchmark, calibration, or locked audit. It requires a local Poppler
installation providing `pdftoppm` and `pdftotext` on `PATH`:

```bash
python3.12 -m venv ../v37-test
../v37-test/bin/python -m pip install -r requirements-release-v2_5.txt
../v37-test/bin/python -m pytest -q -s tests/release/test_figure3_evidence_sync_v3_7.py
```
