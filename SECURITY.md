# Security Policy

> Last updated: 2026-07-14
>
> Document version: 1.0

## Read this before executing anything

Treat this repository as untrusted input until you have reviewed the exact commit
you intend to run. Do not pipe a remote download into Python or a shell. Do not
assume that a GitHub link, a favorable AI review, or a previous safe version makes
the current source safe.

Even the `check` action executes local Python code. Read the complete script
before running `check`, `apply`, or `restore`.

This warning is unusually important because the target is an AI coding agent.
Depending on the permissions a user grants it, Codex may access private source
code, task history, account-linked state, and local tools. A malicious patcher
could change the application before it starts and then act with that trust.

## Security status

This project is an experimental, unofficial workaround. It has no relationship
to, endorsement from, or support commitment by OpenAI.

Applying the patch deliberately:

- Modifies `/Applications/ChatGPT.app` or the bundle selected with `--app`.
- Invalidates OpenAI's Developer ID resource seal.
- Re-signs the application and nested code with an ad hoc signature.
- Grants `disable-library-validation` to the re-signed application.
- May affect Keychain, App Group, firewall, Gatekeeper, or other identity-bound
  behavior.

The original OpenAI signature can return only through exact restoration from the
version-specific backup or by reinstalling the official application.

## Current expected source behavior

Do not trust this list without comparing it with the source at your commit.

At the reviewed version, `patch_codex_question_timeout.py`:

- Uses only the Python standard library.
- Contains no HTTP client, socket client, telemetry, updater, or download code.
- Invokes `/usr/bin/codesign` for inspection, dry runs, signing, and validation.
- Invokes `/bin/ps` and `/usr/lib/libproc.dylib` for exact-bundle process checks.
- Reads the selected app bundle and its external version-specific backup.
- Writes only to the selected app bundle, its dedicated backup tree, and private
  staging directories created under that backup tree.
- Does not read or write Codex project directories, task databases, settings,
  caches, browser profiles, cookies, tokens, or authentication files.

The default backup tree is:

```text
~/Library/Application Support/Codex/Patch Backups/question-timeout/
```

The local backup manifest records the selected application path, hashes, modes,
version, build, and signing inventory. It stays on the local machine unless the
user separately publishes or copies it.

## Minimum independent review

Before the first execution:

1. Record the exact Git commit.
2. Confirm the tracked file list contains only expected public project files.
3. Read the complete Python script, not only the README or a generated summary.
4. Inspect every import, subprocess command, dynamic-library call, and write
   primitive.
5. Confirm there is no network, credential, browser-profile, or user-data access.
6. Verify the exact original and patched markers and the one-byte invariant.
7. Verify the ASAR integrity, signing, backup, and restoration logic.
8. Ask a trusted developer or separately controlled agent to perform an
   independent review without executing the script.
9. Resolve every important finding against the actual source before continuing.
10. Test a complete copied application bundle before modifying the installed app.

The full commands and reviewer prompt are in
[audit-test-apply-and-restore.md](docs/how-to/audit-test-apply-and-restore.md).

## Stop conditions

Do not apply the patch if any of these are true:

- You did not read or independently review the complete script.
- The repository, commit, or source differs from what you reviewed.
- `check` reports anything other than `ready` for an original app.
- The original app does not pass the strict OpenAI signature requirement.
- More than one candidate marker exists or the semantic anchors changed.
- The planned patch changes more than one JavaScript content byte.
- The backup cannot be created and validated outside the app bundle.
- Codex or a helper from the selected bundle is still running.
- A copied original app launches but the patched copy does not.
- Restoration does not return exact hashes and the OpenAI signature.

## Reporting security concerns

Do not include passwords, tokens, cookies, private source code, personal paths,
backup manifests, or other sensitive data in a public GitHub issue.

For a non-sensitive defect, open a repository issue with the affected public
commit, Codex version, build, status output, and redacted error text. If a report
would require sensitive evidence, withhold that evidence until a private channel
has been agreed with the repository owner.

## Security boundaries

This project cannot protect against:

- A malicious future repository commit.
- A compromised GitHub account, dependency source, or local Python interpreter.
- Server-side request expiration or backend behavior.
- App termination, network failure, account expiry, or unrelated Codex defects.
- Copies or caches of Git history that existed before a later history rewrite.

An official setting that preserves the vendor signature remains the preferred
solution.
