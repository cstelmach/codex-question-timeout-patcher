# Codex Question Timeout Patcher

> Last updated: 2026-07-20
>
> Documentation version: 1.4

An experimental, reversible macOS workaround that keeps Codex
`request_user_input` questions pending instead of submitting a timer-generated
empty answer.

## Warning

This is an unsupported modification of the Codex desktop application.

Do not run this script merely because it is linked from a GitHub issue. Read the
entire script at the exact commit you intend to use, inspect every subprocess and
write operation, and preferably obtain an independent review. Even `check`
executes local Python code, so source review must happen before the first command.

Codex may be allowed to access private source code, task history, account-linked
state, and tools on your computer. A malicious or incorrect application patcher
could abuse that trust. Treat this repository as untrusted input until you or a
reviewer you trust have verified it.

Applying the patch replaces OpenAI's Developer ID resource seal with an ad hoc
signature. This may affect team-restricted Keychain or App Group access on some
systems. Keep the generated backup and restore immediately if authentication or
normal application data is unavailable.

The ad hoc signature also grants `disable-library-validation` so the re-signed
application can load its re-signed nested frameworks. This reduces macOS library
loading hardening while the patch is installed.

This project is for the macOS desktop bundle at:

```text
/Applications/ChatGPT.app
```

It is not a Linux, Windows, or standalone Codex CLI workaround.

## Background

[OpenAI Codex issue #28969][issue] requests a setting to disable automatic
question resolution. [PR #28235][timer-pr] introduced the upstream timer policy
that eventually submits an empty response when the user does not interact.

The immediate community lead for inspecting the generated frontend bundle came
from [@n00mkrad's VS Code extension analysis][n00mkrad-comment]. An earlier
instruction-only workaround was shared by [@fcnjd][fcnjd-comment]. This project
credits those contributions and documents the later desktop inspection,
integrity reconstruction, signing, backup, and acceptance work separately.

The macOS desktop bundle contains a separate JavaScript timer controller. This
patcher changes one equal-length byte sequence in that controller:

```javascript
if(e.method===`item/tool/requestUserInput`){this.trackRequest(
```

to:

```javascript
if(e.method===`item/tool/xequestUserInput`){this.trackRequest(
```

The changed method name exists only in the timeout controller's comparison. The
actual request, question UI, answer submission, and MCP elicitation branch remain
unchanged.

## Safety model

This is deliberately more than a raw search-and-replace script.

Before writing, the patcher verifies:

- The bundle identifier is `com.openai.codex`.
- The original app is signed by OpenAI team `2DC432GLL2`.
- Exactly one original or patched marker exists.
- The marker is inside one non-unpacked ASAR entry.
- The surrounding timer semantics still match the reviewed contract.
- The ASAR entry hash and block hashes are valid.
- The ASAR raw-header hash matches `ElectronAsarIntegrity` in `Info.plist`.
- The planned patch changes exactly one JavaScript content byte.
- Every nested signing target matches the reviewed identity and entitlement
  contract.
- The three framework and plugin targets that changed in build `5440` have either
  the reviewed older empty entitlement set or the reviewed shared entitlement set.
- Build `5488` uses a reviewed calendar entitlement profile across the signing
  graph, with one exact source-only library-validation exception for
  `Codex (Service).app`.

Applying the patch:

- Creates a version-specific, overwrite-never backup outside the app.
- Backs up the ASAR, `Info.plist`, and every file identified by the reviewed
  signing plan and signing dry run.
- Recalculates Electron entry, block, and header integrity metadata.
- Uses private staging directories and ordered replacement.
- Re-signs nested code and the app with a validated ad hoc signature.
- Reopens and validates the installed result.
- Attempts exact restoration if an in-process apply step fails.

Restoration reloads the trusted backup before requiring the current bundle pair
to be valid. This allows recovery from interrupted ASAR and `Info.plist` writes.

Electron documents the underlying integrity layers in its
[ASAR integrity guide][electron-asar].

## User-data boundary

The patcher does not read, copy, or modify existing state in:

```text
~/.codex
project directories
task databases
settings
caches
```

It creates only its dedicated recovery tree under:

```text
~/Library/Application Support/Codex/Patch Backups/question-timeout/
```

It does not inspect or modify other contents of Codex Application Support.

If a copied test app is launched with isolated `HOME`, `CODEX_HOME`, or
`CODEX_ELECTRON_USER_DATA_PATH`, it will show an empty local task history by
design. Apply to the installed app and launch it normally to retain existing
projects, settings, and tasks.

## Documentation

- [Changelog](CHANGELOG.md) records the initial publication, compatibility
  updates for changed Codex signing contracts, and documentation corrections.
  Entries are dated because the project does not currently use tagged releases.
- [Finder actions](_human-actions/README.md) provide optional double-clickable
  wrappers for checking, applying, and restoring the patch. The guide explains
  their local framework dependency and the safe update workflow.
- [Security policy and review expectations](SECURITY.md) explains why this
  patcher must be treated as untrusted until independently reviewed. It maps the
  current attack surface, expected commands and writes, signing consequences,
  user-data boundary, and safe reporting practices.
- [Discovery and technical design](docs/explanation/discovery-and-technical-design.md)
  records the public community leads, attribution boundaries, desktop bundle
  inspection, one-byte patch invariant, Electron integrity chain, signing model,
  and copied-bundle acceptance evidence.
- [Audit, test, apply, and restore](docs/how-to/audit-test-apply-and-restore.md)
  provides a complete workflow for people and reviewing agents. It starts with a
  no-execution source audit, then covers copied-bundle testing, live installation,
  runtime acceptance, updates, stop conditions, and exact restoration.

## Requirements

- macOS on Apple Silicon
- Python 3.9 or newer
- `/usr/bin/codesign`
- Codex installed as `/Applications/ChatGPT.app`
- Enough free disk space for the version-specific recovery backup

The patcher uses only the Python standard library and macOS system tools.

## Installation

```bash
git clone https://github.com/cstelmach/codex-question-timeout-patcher.git
cd codex-question-timeout-patcher
git rev-parse HEAD
```

Record that commit hash. Review and execute the same commit, preferably in a
detached checkout, instead of relying on a moving branch name.

## Optional Finder actions

macOS users with the local human-actions framework can use the
[double-clickable actions](_human-actions/README.md) for `check`, `apply`, and
`restore`. They call the same patcher commands and do not bypass its signature,
backup, process, or compatibility checks.

## Step 1: Check compatibility

`check` is the default, read-only action:

```bash
python3 patch_codex_question_timeout.py check
```

A compatible original application reports:

```text
Status: ready
OpenAI signature: valid
```

The command also prints current and planned ASAR and `Info.plist` hashes. It does
not create the backup or temporary files.

Do not apply if the status is `unsupported`, `untrusted`,
`recovery-required`, or `patched-unrestorable`.

## Step 2: Completely quit Codex

Use Cmd-Q and allow active work to stop. The patcher checks executable paths and
refuses to apply or restore while any process from the selected app bundle is
running.

## Step 3: Apply

```bash
python3 patch_codex_question_timeout.py \
  apply --acknowledge-invalid-signature
```

A successful apply reports:

```text
Patch applied, Electron integrity verified, and ad hoc signing validated.
```

The default backup location is:

```text
~/Library/Application Support/Codex/Patch Backups/question-timeout/
```

Backups are stored under `<version>-<build>/`. Never remove the matching backup
while that application version remains patched.

If you pass a custom `--backup-root`, it must be on the same filesystem as the
selected application bundle. The patcher checks this and refuses otherwise.

Applying again to the same patched build is a safe no-op.

## Step 4: Launch normally

```bash
open /Applications/ChatGPT.app
```

Do not add isolated data-path environment variables if you expect existing local
projects and task history.

## Step 5: Verify the pending question

In a disposable Plan Mode task, ask:

```text
Ask exactly one blocking question using request_user_input.
Provide two options named Alpha and Beta.
Do not continue until I answer.
```

When the question appears:

1. Leave it unanswered for at least 180 seconds.
2. Return to Codex.
3. Confirm the original question remains visible.
4. Confirm no empty answer was submitted.
5. Select `Alpha`.
6. Confirm the same task resumes with `Alpha`.
7. Send one ordinary follow-up message.

## Check the patched state

```bash
python3 patch_codex_question_timeout.py check
```

Expected output includes:

```text
Status: patched
OpenAI signature: invalid (replaced by validated ad hoc signature)
```

The script separately verifies the generic ad hoc signature, Electron integrity,
application identity, current hashes, and matching backup manifest.

## Restore

Completely quit Codex, then run:

```bash
python3 patch_codex_question_timeout.py restore
```

A successful restore reports:

```text
Original files restored and OpenAI Developer ID signature verified.
```

Restore verifies the original manifest hashes, file modes, and strict OpenAI
signature. Running restore again on an already original app is a safe no-op.

If the patched app does not open, run restore from Terminal.

## Status values

| Status | Meaning |
|---|---|
| `ready` | Compatible original app with a valid OpenAI signature. |
| `patched` | Valid patch and ad hoc signature with a matching backup. |
| `patched-unrestorable` | Valid patch but no trusted matching backup. |
| `recovery-required` | Interrupted or mixed file state; run restore. |
| `unsupported` | The reviewed structural or semantic contract changed. |
| `untrusted` | Source signature or backup identity validation failed. |

Only `ready` and `patched` return a successful `check` status.

## After a Codex update

Run `check` again:

```bash
python3 patch_codex_question_timeout.py check
```

Generated JavaScript filenames and offsets may change. They are discovered
dynamically. The script does not use a broader fallback when semantic anchors or
signing contracts change.

Build `5440` added the existing shared entitlement set to the Codex framework,
Sparkle framework, and dock tile plugin. The patcher accepts either that exact
contract or the older empty contract for those three targets. It records the
effective contract in each version-specific backup so older restore manifests
remain valid.

Build `5488` added a calendar entitlement profile across the reviewed signing
graph and a source-only library-validation exception for
`Codex (Service).app`. The patcher accepts only the exact reviewed profile and
service path.

If the updated app reports `ready`, review its planned hashes and apply again. If
it reports `unsupported`, stop until the changed contract has been reviewed.
See the [changelog](CHANGELOG.md) for previously reviewed compatibility changes.

## Author-observed local verification

The repository does not include raw test logs or screenshots. Local development
verification included:

- A complete copied application bundle.
- Baseline and patched copied-app launches.
- One-byte content-diff verification.
- Electron entry, block, and header integrity.
- Original and patched signing-contract validation.
- Old and new nested entitlement-contract validation.
- A complete `codesign --dryrun` over build `5440` after its entitlement change.
- Exact calendar-profile and service-exception fixtures for build `5488`.
- A complete `codesign --dryrun` over all 15 build `5488` signing targets.
- Matching, missing, tampered, and symlinked backup fixtures.
- Both interrupted ASAR and `Info.plist` pair combinations.
- Missing backed signing-helper recovery.
- Running-process refusal with no writes.
- Idempotent apply and restore.
- Exact restoration of backed file-content hashes and modes.
- Return of the strict OpenAI signature after restore.
- A real pending question left visible for 186 seconds.
- Successful answer and continuation in the same task.
- Preservation of existing projects and task history in the live app.

The copied-bundle engineering test used version `26.707.62119`, build `5211`.
The live accepted test used version `26.707.71524`, build `5263`. The generated
target entry changed between those builds and was discovered automatically.
Compatibility inspection for version `26.707.91948`, build `5440`, confirmed the
same timer semantics, signing graph, runtime metadata, and file inventory. Its
three reviewed nested entitlement changes passed the complete signing dry run.
Compatibility inspection for version `26.715.21425`, build `5488`, confirmed the
same timer semantics and signing inventory. Its entitlement profile and signing
dry run passed without modifying the application. Runtime product acceptance for
build `5488` remains pending.

## Limitations

- This disables the desktop app's timer tracking for all
  `request_user_input` requests.
- It does not change server-side request lifetimes.
- It cannot preserve OpenAI team-bound entitlements under an ad hoc signature.
- It does not protect against app termination, network failure, account expiry,
  or backend timeouts.
- It does not install an updater, daemon, launch agent, or scheduled job.
- Compatible app updates require manual reapplication.

An official setting remains the preferred long-term solution.

## License

The patcher and its documentation are available under the [MIT License](LICENSE).
The license covers this repository's original work. It does not grant rights to
OpenAI's Codex application, names, trademarks, or other third-party materials.

[issue]: https://github.com/openai/codex/issues/28969
[timer-pr]: https://github.com/openai/codex/pull/28235
[electron-asar]: https://www.electronjs.org/docs/latest/tutorial/asar-integrity
[fcnjd-comment]: https://github.com/openai/codex/issues/28969#issuecomment-4847883145
[n00mkrad-comment]: https://github.com/openai/codex/issues/28969#issuecomment-4949555047
