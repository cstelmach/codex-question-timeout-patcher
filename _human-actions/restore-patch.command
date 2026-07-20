#!/bin/bash
# Double-click stub for restore-patch.action. Locates the sibling definition and the
# shared runner, then hands off. #!/bin/bash (not env) because a Finder-launched
# Terminal has no guaranteed Homebrew PATH; system bash 3.2 is deterministic.
DIR=$(cd "$(dirname "$0")" && pwd)
DEF="$DIR/restore-patch.action"
RUNNER="$HOME/local/code/scripts/human-actions/lib/runner.sh"
if [ ! -f "$RUNNER" ]; then
  printf 'ERROR: runner not found: %s\n' "$RUNNER" >&2
  printf 'Press Enter to close...'; read -r _; exit 1
fi
if [ ! -f "$DEF" ]; then
  printf 'ERROR: definition not found: %s\n' "$DEF" >&2
  printf 'Press Enter to close...'; read -r _; exit 1
fi
exec /bin/bash "$RUNNER" "$DEF"
