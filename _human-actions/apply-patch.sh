#!/bin/bash

set -u

NODE_REPL_PATTERN='^/Applications/ChatGPT\.app/Contents/Resources/cua_node/bin/node_repl$'
PATCHER="$HOME/local/code/scripts/codex-question-timeout-patcher/patch_codex_question_timeout.py"

if [ ! -f "$PATCHER" ]; then
  printf 'ERROR: patcher not found: %s\n' "$PATCHER" >&2
  exit 2
fi

pids=$(/usr/bin/pgrep -f "$NODE_REPL_PATTERN" 2>/dev/null || true)
if [ -n "$pids" ]; then
  printf 'Lingering Codex node_repl processes were found:\n'
  for pid in $pids; do
    /bin/ps -p "$pid" -o pid=,command= 2>/dev/null || true
  done
  printf 'Terminate all processes matching this exact path before applying? [y/N]: '
  IFS= read -r answer || {
    printf '\nAborted.\n'
    exit 0
  }
  case "$answer" in
    y|Y|yes|YES|Yes) ;;
    *) printf 'Aborted. No processes were terminated.\n'; exit 0 ;;
  esac

  /usr/bin/pkill -TERM -f "$NODE_REPL_PATTERN" 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    /usr/bin/pgrep -f "$NODE_REPL_PATTERN" >/dev/null 2>&1 || break
    /bin/sleep 0.5
  done
  if /usr/bin/pgrep -f "$NODE_REPL_PATTERN" >/dev/null 2>&1; then
    printf 'ERROR: one or more node_repl processes did not stop.\n' >&2
    exit 2
  fi
fi

exec /usr/bin/python3 "$PATCHER" apply --acknowledge-invalid-signature
