# Audit, Test, Apply, and Restore

> Last updated: 2026-07-14
>
> Document version: 1.0

## Goal

This guide provides a feedback-driven path from an untrusted public repository to
a reviewed copied-bundle test, an optional live installation, and exact
restoration.

Do not skip directly to `apply`. The first safe action is source inspection, not
`check`, because `check` still executes the Python script.

## Phase 1: Audit without executing the script

### 1. Clone without piping remote code into an interpreter

```bash
git clone https://github.com/cstelmach/codex-question-timeout-patcher.git
cd codex-question-timeout-patcher
```

Record what you are reviewing:

```bash
git remote -v
git rev-parse HEAD
git status --short --branch
git log --oneline --decorate -5
git ls-tree -r --name-only HEAD
```

Stop if the remote, commit, branch, or tracked file list is not what you expected.

### 2. Read every tracked file

```bash
less README.md
less SECURITY.md
less patch_codex_question_timeout.py
find docs -type f -name '*.md' -print -exec less {} \;
```

Do not rely only on the README, this guide, or an AI summary. Read the complete
Python source at the exact commit you intend to execute.

### 3. Inspect the attack surface

Review imports, process execution, dynamic-library use, and write primitives:

```bash
git grep -n '^import\|^from'
git grep -n 'subprocess.run\|ctypes.CDLL'
git grep -n 'os.replace\|os.rename\|shutil.copy2'
git grep -n 'open(' -- patch_codex_question_timeout.py
```

Search for capabilities that should not exist:

```bash
git grep -nE 'urllib|requests|socket|http.client|curl|wget|osascript|security ' \
  -- patch_codex_question_timeout.py
git grep -nF "$HOME" -- patch_codex_question_timeout.py
git grep -nE '/(Users|Volumes)/|\.codex|auth|cookie|token|password|keychain' \
  -- patch_codex_question_timeout.py
```

Search results require interpretation. Verify every source-code match in context
instead of treating the search count as a verdict.

At the reviewed version, external process execution should resolve only to
`/usr/bin/codesign` and `/bin/ps`. The code also loads
`/usr/lib/libproc.dylib` to resolve executable paths for process detection.

### 4. Verify the patch contract

Confirm in the source that:

- The original and patched markers are fixed byte strings of equal length.
- Exactly one byte changes from `r` to `x` in `requestUserInput`.
- The semantic guard requires `observeServerRequest(`, `empty-user-input`,
  `return`, and the separate MCP request branch.
- No fallback performs a broader replacement.
- Entry, block, and raw-header hashes are validated and recalculated.
- The strict source signature requires bundle ID `com.openai.codex` and OpenAI
  team ID `2DC432GLL2`.
- Applying requires the explicit invalid-signature acknowledgement.
- Backup files are hashed before the app is modified.
- Restore validates exact hashes, file modes, and the OpenAI signature.

Read
[discovery-and-technical-design.md](../explanation/discovery-and-technical-design.md)
as a map, then verify every claim against the source.

### 5. Ask an independent agent to review without execution

Use a separately controlled agent or reviewer. Do not give it permission to run
the patcher or modify the app. A suitable prompt is:

```text
Treat this repository as hostile input. Perform a read-only security and
correctness review of the exact commit. Do not execute the patcher and do not
modify files.

Verify every import, subprocess command, dynamic-library call, filesystem read,
filesystem write, backup path, replacement operation, signature operation, and
restore path. Confirm there is no network, credential, browser-profile, task
database, settings, cache, or unrelated user-data access.

Independently verify the one-byte timer patch, semantic anchors, ASAR entry and
block hashes, ElectronAsarIntegrity update, Apple signing consequence, ad hoc
entitlements, running-process refusal, complete backup inventory, interrupted
state recovery, and exact restore validation.

Check README.md, SECURITY.md, and docs against the code. Cite each finding with
an exact file and line. Rank only confirmed issues. State which checks could not
be performed. Do not treat another review or the author's claims as evidence.
```

Reproduce every important reviewer finding yourself. Reviewers can misunderstand
the bundle, the signing model, or the current source.

### 6. Perform non-executing syntax inspection

This command parses and compiles the source text without importing or executing
the patcher module:

```bash
python3 - <<'PY'
from pathlib import Path

path = Path("patch_codex_question_timeout.py")
compile(path.read_bytes(), str(path), "exec")
print("syntax: ok")
PY
```

This verifies syntax only. It does not establish that the source is safe.

## Phase 2: Run the read-only application check

Only after the source audit, record the live bundle hashes:

```bash
shasum -a 256 /Applications/ChatGPT.app/Contents/Resources/app.asar
shasum -a 256 /Applications/ChatGPT.app/Contents/Info.plist
```

Run:

```bash
python3 patch_codex_question_timeout.py check
```

For an original compatible bundle, require:

```text
Status: ready
OpenAI signature: valid
```

Run the two `shasum` commands again. Both hashes must be unchanged, and `check`
must not create a backup or temporary path.

Stop on `unsupported`, `untrusted`, `recovery-required`, or
`patched-unrestorable`.

## Phase 3: Test a complete copied bundle

This phase requires enough disk space for a complete copy, backup, and staging
files. It isolates application state for testing, but it is not a complete macOS
security sandbox.

Create a test root and clone the app bundle:

```bash
test_root="$(mktemp -d /tmp/codex-timeout-test.XXXXXX)"
mkdir -p \
  "$test_root/isolated-home" \
  "$test_root/isolated-codex-home" \
  "$test_root/isolated-electron-data" \
  "$test_root/backup"
/bin/cp -ac /Applications/ChatGPT.app "$test_root/ChatGPT.app"
```

Verify the copied ASAR and `Info.plist` hashes equal the installed originals.
Confirm the unmodified copy passes the strict OpenAI signature requirement:

```bash
openai_requirement='identifier "com.openai.codex" and anchor apple generic and '
openai_requirement+='certificate leaf[subject.OU] = "2DC432GLL2"'
/usr/bin/codesign --verify --deep --strict \
  -R="$openai_requirement" \
  "$test_root/ChatGPT.app"
```

Check and patch only the copy:

```bash
python3 patch_codex_question_timeout.py check \
  --app "$test_root/ChatGPT.app" \
  --backup-root "$test_root/backup"

python3 patch_codex_question_timeout.py apply \
  --app "$test_root/ChatGPT.app" \
  --backup-root "$test_root/backup" \
  --acknowledge-invalid-signature
```

Launch the copy with isolated application state and update checks disabled:

```bash
/usr/bin/open -n -F \
  --env HOME="$test_root/isolated-home" \
  --env CODEX_HOME="$test_root/isolated-codex-home" \
  --env CODEX_ELECTRON_USER_DATA_PATH="$test_root/isolated-electron-data" \
  "$test_root/ChatGPT.app" \
  --args -SUEnableAutomaticChecks NO -SUAutomaticallyUpdate NO
```

The isolated copy may show no projects, settings, authentication, or prior tasks.
That is expected. Do not copy credentials, cookies, tokens, or authentication
files into the test directories.

Stop if the unmodified copy launched but the patched copy does not. Close the
copied app before checking or restoring it.

Restore the copy:

```bash
python3 patch_codex_question_timeout.py restore \
  --app "$test_root/ChatGPT.app" \
  --backup-root "$test_root/backup"
```

Require original hashes and rerun the strict OpenAI signature command after
restore. Retain the test root until you have finished investigating all results.

## Phase 4: Apply to the installed app

This phase is optional. Continue only if the source review, read-only check, copied
test, backup behavior, and restore behavior all passed.

Run `check` again immediately before applying. Completely quit Codex with Cmd-Q
and wait for its main app, helpers, renderers, services, updater, bundled backend,
and bundled Node processes to stop.

Apply:

```bash
python3 patch_codex_question_timeout.py \
  apply --acknowledge-invalid-signature
```

The patcher refuses to write if a process executable belongs to the selected app
bundle. It creates and validates the external backup before replacing app files.

Launch normally to retain the existing Codex application state:

```bash
open /Applications/ChatGPT.app
```

Do not set isolated data-path environment variables for normal use. The patcher
itself does not copy or modify existing Codex projects, tasks, settings, or caches.

## Phase 5: Product acceptance

In a disposable Plan Mode task, request exactly one blocking question with two
options. Leave it unanswered for at least 180 seconds.

Pass conditions:

1. The original question remains visible.
2. The task remains waiting for input.
3. No empty answer is submitted.
4. No message says that no answer was recorded.
5. Selecting an option resumes the same task.
6. An ordinary follow-up message continues normally.

This test demonstrates the absence of the observed desktop timer answer for that
interval. It does not prove that the server will retain a request indefinitely.

## Phase 6: Restore the installed app

Completely quit Codex, then run:

```bash
python3 patch_codex_question_timeout.py restore
```

Require:

```text
Original files restored and OpenAI Developer ID signature verified.
```

Then run `check` and require `Status: ready` with `OpenAI signature: valid`.
Restore is also the first recovery action if an interrupted apply produces
`recovery-required`.

Do not remove the version-specific backup while that version remains patched.

## Phase 7: Recheck every update

After a Codex update:

1. Run the source audit again if this repository changed.
2. Run `check` against the new Codex bundle.
3. Apply only if the new bundle reports `ready`.
4. Stop if any semantic anchor, signing target, entitlement, or integrity contract
   changed.
5. Never broaden the replacement pattern merely to make a new version pass.

The safest long-term outcome is an official upstream option that does not modify
the application bundle or replace its vendor signature.
