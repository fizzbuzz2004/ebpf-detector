#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Der Smoke-Test benötigt Linux." >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "Für den Root-Anomalietest bitte mit sudo starten:" >&2
  echo "  sudo $0" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d /tmp/ebpf-detector-lab.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

printf '\n[1/5] Normale Prozessstarts\n'
/bin/echo "detector smoke test"
/usr/bin/id

printf '\n[2/5] getdents64-Verzeichnisenumeration\n'
find /etc -maxdepth 1 -type f -print >/dev/null

printf '\n[3/5] Fehlgeschlagener Exec-Versuch\n'
if /bin/bash -c 'exec /definitely-not-a-real-executable' 2>/dev/null; then
  echo "Unerwartet: nicht vorhandenes Executable wurde gestartet." >&2
  exit 1
else
  echo "Erwarteter Fehler: fehlgeschlagener execve wurde ausgeführt."
fi

printf '\n[4/5] Root-Prozess startet ausführbare Datei aus /tmp\n'
cp /usr/bin/true "$TMP_DIR/payload"
chmod 0755 "$TMP_DIR/payload"
/bin/bash -c '( "$1" ); /bin/true' _ "$TMP_DIR/payload"

printf '\n[5/5] Fehlgeschlagener Kernel-Modul-Ladeversuch (harmloser Text statt Modul)\n'
if command -v insmod >/dev/null 2>&1; then
  printf 'not-a-kernel-module\n' > "$TMP_DIR/invalid.ko"
  if insmod "$TMP_DIR/invalid.ko" >/dev/null 2>&1; then
    echo "Unerwartet: Testdatei wurde als Modul akzeptiert." >&2
    exit 1
  else
    echo "Erwarteter Fehler: Kernel hat die ungültige Testdatei abgelehnt."
  fi
else
  echo "insmod fehlt; optional installieren: sudo apt install kmod" >&2
fi

cat <<'MSG'

Smoke-Test abgeschlossen. Im Daemon sollten sichtbar sein:
- exec_attempt und process_exec für erfolgreiche Starts
- exec_failure für den absichtlich fehlgeschlagenen Start
- directory_enum auf DEBUG-Level
- root_exec_from_writable_path (heuristischer Alarm)
- module_syscall_attempt plus module_syscall_result (falls insmod vorhanden)

Der Smoke-Test lädt kein echtes Kernelmodul und verändert keine Kernelparameter.
MSG
