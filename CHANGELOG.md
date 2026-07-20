# Changelog

> Last updated: 2026-07-20
>
> Document version: 1.1

This file records notable changes to the patcher and its public documentation.
The project does not currently use tagged releases, so entries are grouped by
date and linked to the corresponding commits.

## Unreleased

### Added

- Added this changelog and linked it from the README.
- Added optional Finder actions for checking, applying, and restoring the patch.
- Added a self-contained action guide and linked it from the main README.

## 2026-07-17

### Fixed

- Added exact support for the calendar entitlement profile introduced in Codex
  desktop build `5488`.
- Restricted the new source entitlement exception to the reviewed
  `Codex (Service).app` path.
- Bound new backups to their entitlement profile while preserving restoration
  from older schema-3 manifests.
- Documented that build `5488` passed read-only compatibility inspection and a
  complete signing dry run, while runtime product acceptance remains pending.

Commit: [`c16b76e`](https://github.com/cstelmach/codex-question-timeout-patcher/commit/c16b76e)

## 2026-07-16

### Fixed

- Added support for the shared entitlement contract introduced on three nested
  signing targets in Codex desktop build `5440`.
- Preserved both the reviewed older empty contract and the newer shared contract
  for compatible historical backups.
- Stored the effective signing policy in new backup manifests.

Commit: [`7e781bf`](https://github.com/cstelmach/codex-question-timeout-patcher/commit/7e781bf)

## 2026-07-14

### Added

- Published the reversible macOS question-timeout patcher.
- Added fail-closed ASAR and signing validation, version-specific recovery
  backups, exact restoration, public security guidance, attribution, and an MIT
  license.
- Documented Electron integrity reconstruction, ad hoc signing consequences,
  copied-bundle testing, and runtime acceptance steps.

### Changed

- Clarified that published runtime results are author-observed without raw test
  artifacts.
- Required users to audit and execute the same recorded commit.
- Corrected restoration claims to cover backed file hashes and modes.
- Documented the same-filesystem requirement for custom backup roots.

Commits: [`b531e26`](https://github.com/cstelmach/codex-question-timeout-patcher/commit/b531e26),
[`f7a1132`](https://github.com/cstelmach/codex-question-timeout-patcher/commit/f7a1132)
