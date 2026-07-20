# _human-actions

Double-clickable wrappers for the patcher's three normal operations. Each action
has two files:

- `<name>.command`: opens Terminal and starts the shared runner.
- `<name>.action`: declares the exact command and displayed safety information.

The runner shows the action description and exact command, asks for confirmation,
executes it, and keeps the result visible.

## Dependency

Finder launching is macOS-only. These actions require the local human-actions
framework at:

```text
~/local/code/scripts/human-actions/
```

They also expect this repository at:

```text
~/local/code/scripts/codex-question-timeout-patcher/
```

The definitions pin `/usr/bin/python3`. If the repository is elsewhere, update
the script path in each `.action` file before running it.

The human-actions framework is local-only and is not installed by this repository.
Without it, use the terminal commands in the main [README](../README.md).

## Actions

| Action | Wraps | Notes |
|---|---|---|
| `check-patch` | `patcher check` | Read-only; does not create a backup. |
| `apply-patch` | `patcher apply --acknowledge-invalid-signature` | Quit Codex first. |
| `restore-patch` | `patcher restore` | Quit Codex first. |

## Apply after a Codex update

1. Review the exact repository commit and the complete patcher source.
2. Double-click `check-patch.command` and confirm the result says `Status: ready`.
3. Completely quit Codex and wait for its helpers to stop.
4. Double-click `apply-patch.command`, review the displayed command, and confirm.
5. Launch Codex normally from `/Applications/ChatGPT.app`.
6. Follow the pending-question test in the main [README](../README.md).

Applying creates a version-specific backup, reconstructs Electron integrity, and
replaces OpenAI's Developer ID seal with an ad hoc signature. Do not continue if
the check reports `unsupported`, `untrusted`, or a recovery state.

## Restore

1. Completely quit Codex.
2. Double-click `restore-patch.command`.
3. Review the displayed command and confirm.
4. Require the result to report that the original files and OpenAI signature were
   restored.

Read the [security policy](../SECURITY.md) and the full
[audit, test, apply, and restore guide](../docs/how-to/audit-test-apply-and-restore.md)
before first use.

## Shell usage

Run an action directly with:

```bash
/bin/bash ~/local/code/scripts/human-actions/lib/runner.sh \
  ~/local/code/scripts/codex-question-timeout-patcher/_human-actions/check-patch.action
```

Add `--print-only` to print the assembled argv without executing it.

## Add more actions

Re-run the `cmd-human-actions-scaffold` skill or use:

```bash
/bin/bash ~/local/code/scripts/human-actions/new-action.sh
```

Commit `_human-actions/` normally. Run history is stored under
`~/.local/state/human-actions/`.
