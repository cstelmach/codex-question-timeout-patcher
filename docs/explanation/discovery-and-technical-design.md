# Discovery and Technical Design

> Last updated: 2026-07-14
>
> Document version: 1.0

## Purpose

This document records how the workaround was derived, which public contributors
provided the key leads, what was independently verified in the macOS desktop
bundle, and why the final implementation is more involved than a text replacement.

It separates public attribution from later engineering work. It does not claim
that one person discovered or implemented every part of the workaround.

## Community trail and attribution

The investigation began with
[OpenAI Codex issue #28969](https://github.com/openai/codex/issues/28969), which
documents requests being automatically resolved while users are away.

Three public comments materially narrowed the investigation:

1. On 2026-06-30, [@fcnjd shared an instruction-only workaround][fcnjd]. It asked
   the agent to omit `autoResolutionMs`, showing that the parameter and client
   behavior were central to the problem.
2. On 2026-07-12, [@n00mkrad identified the generated VS Code frontend call][n00mkrad]
   `trackRequest(e.params.threadId,e.id,"empty-user-input")` and described editing
   the generated extension bundle. This was the direct methodological lead for
   inspecting the generated desktop frontend bundle rather than only the
   open-source CLI.
3. On 2026-07-13, [@Astro-Han reported the same three-argument call][astro-han]
   in the macOS desktop package and supplied timing evidence showing that omitted
   `autoResolutionMs` requests still received empty answers.

The instruction workaround is useful in clients that honor the parameter. Public
follow-up reports show that some Plan Mode clients ignore it, so this project does
not treat instructions as a universal fix.

## Upstream timer behavior

[OpenAI PR #28235][timer-pr] added an auto-resolution policy for
`request_user_input`. Its public summary describes a hidden grace period, a visible
countdown, and submission of an empty answer when the user does not interact.

The macOS desktop package contains a JavaScript timer controller with this branch:

```javascript
if(e.method===`item/tool/requestUserInput`){this.trackRequest(
```

The same controller associates the request with `empty-user-input`, returns from
that branch, and then handles `mcpServer/elicitation/request` separately.

## Read-only bundle inspection

The desktop application stores its generated frontend code in:

```text
/Applications/ChatGPT.app/Contents/Resources/app.asar
```

The investigation followed these steps before modifying a bundle:

1. Record the bundle identifier, version, build, executable, architecture,
   OpenAI signature result, and hashes of `app.asar` and `Info.plist`.
2. Parse the ASAR header and traverse every non-unpacked file entry.
3. Search entry contents for the exact `requestUserInput` timer marker.
4. Require exactly one original marker and no patched marker.
5. Confirm the bounded preceding context contains `observeServerRequest(`.
6. Confirm the same branch contains `empty-user-input` followed by `return`.
7. Confirm the next request branch refers to `mcpServer/elicitation/request`.
8. Validate entry bounds, the entry content hash, and every block hash.
9. Validate the raw ASAR header hash against `ElectronAsarIntegrity` in
   `Info.plist`.

Generated filenames and byte offsets changed between tested Codex builds. The
patcher therefore discovers the entry and offset from the semantic contract. It
does not hardcode the generated filename or use a broad fallback search.

## The one-byte workaround

The patch changes this equal-length sequence:

```text
item/tool/requestUserInput
```

to:

```text
item/tool/xequestUserInput
```

Only the first character of `requestUserInput` changes from `r` to `x`. Both full
markers are the same length, so the ASAR data layout and every later entry offset
remain stable.

The changed comparison exists only in the timer controller. The actual server
request method, question UI, answer submission, and separate MCP elicitation
branch are not renamed.

The patch deliberately does not rename `empty-user-input`. The controller removes
timer state before it handles that action, so changing the action instead could
leave a request without a usable resolution path.

## Electron integrity reconstruction

Electron documents the relevant format in its
[ASAR integrity guide][electron-asar]. The target entry stores:

- A SHA-256 content hash.
- SHA-256 hashes for fixed-size content blocks.
- A block size and integrity algorithm.

macOS packaging also stores the SHA-256 hash of the raw ASAR header under
`ElectronAsarIntegrity` in `Info.plist`. Electron can terminate the application if
the packaged header hash is missing or does not match.

The patcher therefore recalculates:

1. The changed entry content hash.
2. The changed entry block hash.
3. The raw ASAR header hash.
4. The `ElectronAsarIntegrity` value in `Info.plist`.

It serializes the changed header to the exact original byte length and rejects the
operation if that invariant does not hold.

## Apple code-signing consequence

Electron integrity and Apple code signing are separate layers. Apple's
[code-signing guide][apple-signing] explains that application resources,
`Info.plist`, nested code, and code requirements are covered by signature seals.

Changing `app.asar` and `Info.plist` invalidates OpenAI's Developer ID resource
seal. This project cannot recreate OpenAI's private signature.

To make the modified local bundle internally consistent, the patcher:

1. Discovers and validates the expected nested signing graph.
2. Backs up every file that the reviewed signing operation may modify.
3. Performs a `codesign` dry run and compares the possible-file inventory.
4. Re-signs nested code and the main app with an ad hoc signature.
5. Preserves identifiers, runtime flags, and runtime versions.
6. Validates the resulting generic signature and confirms that the strict OpenAI
   requirement no longer passes.

The sanitized ad hoc entitlements include `disable-library-validation` so the
re-signed application can load its re-signed nested frameworks. This is a real
hardening reduction and is disclosed prominently.

## Backup and recovery design

Before modifying the selected app, the patcher creates an overwrite-never backup
for the exact version and build. The current signing contract produces 28 unique
backed files, including `app.asar`, `Info.plist`, nested signed code, and signature
resource files.

Each manifest entry records its relative path, role, byte size, mode, and SHA-256
hash. The manifest also binds the backup to the application path, bundle ID,
version, build, target entry, signing graph, entitlements, and original and planned
hashes.

The two main bundle files cannot be replaced as one atomic filesystem transaction.
The implementation uses ordered same-filesystem replacements and classifies mixed
states as `recovery-required`. Restore loads and validates the external backup
before requiring the current ASAR pair to be valid.

## Validation evidence

Engineering validation used a complete copied app bundle, not only synthetic
files. It compared baseline and patched launches, verified the one-byte target
change and integrity chain, exercised interrupted-pair recovery, and restored the
copy to its original hashes and OpenAI signature.

Product acceptance left a real question unanswered for 186 seconds. The original
question remained visible, no empty answer was submitted, and answering resumed
the same task. Launching the installed app normally preserved its existing
projects and task history.

The copied-bundle test used version `26.707.62119`, build `5211`. The live accepted
test used version `26.707.71524`, build `5263`.

## What this does not establish

The tests do not prove that:

- Every future Codex build is compatible.
- A server-side request will wait forever.
- The patch survives app termination, network failure, or account expiry.
- Ad hoc signing preserves all identity-bound macOS behavior.
- A future repository commit is safe merely because an earlier commit was safe.

Users and their agents should follow the independent workflow in
[audit-test-apply-and-restore.md](../how-to/audit-test-apply-and-restore.md).

[apple-signing]: https://developer.apple.com/library/archive/technotes/tn2206/_index.html
[astro-han]: https://github.com/openai/codex/issues/28969#issuecomment-4960780057
[electron-asar]: https://www.electronjs.org/docs/latest/tutorial/asar-integrity
[fcnjd]: https://github.com/openai/codex/issues/28969#issuecomment-4847883145
[n00mkrad]: https://github.com/openai/codex/issues/28969#issuecomment-4949555047
[timer-pr]: https://github.com/openai/codex/pull/28235
