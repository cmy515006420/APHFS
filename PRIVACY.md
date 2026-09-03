# Public repository privacy and archive-safety audit

Status: PASS when accepted by `tools/validate_public_repository_v1.py` and the
post-push anonymous fresh-clone audit.

This public repository was assembled from a finite explicit allowlist. It
excludes raw calibration and locked role values, protected result containers,
private approval or authorization records, chat transcripts, credentials,
workstation paths, caches, virtual environments, historical review archives,
and unrelated data. Validation is fail-closed for traversal, absolute or
backslash paths, links, special/encrypted members, duplicate or Unicode/case
collisions, CRC failures, secrets, local paths, and unapproved nested archives.
ZIP and DOCX members are recursively inspected.

GitHub publication: completed and publicly verified at https://github.com/cmy515006420/APHFS.
bioRxiv upload and final submission: not performed by this release process.
