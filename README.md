# eBPF Detector — Rust + Aya

Ein Linux-Kernel-Telemetrie- und Detektionssensor in Rust. Der aktuelle Ausbau erfasst `execve` und `execveat` (inklusive fehlgeschlagener Syscalls und bestätigter Image-Wechsel), Fork-/Exit-Beziehungen, Kernel-Modul-Ladeversuche und bestätigte Modul-Ladeereignisse sowie `getdents64`-Metadaten. Die Ereignisse laufen über einen gemeinsamen BPF-Ring-Buffer in einen asynchronen Tokio-Daemon.

> **Reifegrad:** Security-Research-/Portfolio-Prototyp. Das Projekt ist noch kein zertifizierter EDR und kein vollständiger Rootkit- oder DKOM-Detektor. Es verändert keine Kernelstrukturen und versucht nicht, Rootkits aktiv zu entfernen.

## Architektur

```mermaid
flowchart LR
    subgraph Kernel[Linux Kernel]
      A[sys_enter_execve / execveat]
      A2[sys_exit_execve / execveat]
      B[sched_process_fork / exit / exec]
      C[sys_enter/exit_init_module + finit_module]
      D[module_load]
      E[sys_enter/exit_getdents64]
      P[detector-ebpf<br/>no_std / Aya]
      R[(16 MiB BPF RingBuf)]
      L[(Per-CPU lost counter)]
      X[(Per-CPU probe-error counter)]
      A --> P
      A2 --> P
      B --> P
      C --> P
      D --> P
      E --> P
      P --> R
      P --> L
      P --> X
    end
    R --> U[detector-userspace<br/>Tokio AsyncFd]
    L --> U
    X --> U
    U --> V[ABI / Länge / Version validieren]
    V --> H[Prozess- und Modul-Korrelation]
    H --> J[JSON Logs via tracing]
    CMM[detector-common<br/>repr(C) ABI v2] --- P
    CMM --- V
```

## Workspace

```text
ebpf-detector/
├── Cargo.toml
├── README.md
├── .gitignore
├── .github/workflows/ci.yml
├── deploy/
│   └── detector.service
├── scripts/
│   ├── build.sh
│   └── smoke-test.sh
└── crates/
    ├── detector-common/
    │   ├── Cargo.toml
    │   └── src/lib.rs
    ├── detector-ebpf/
    │   ├── Cargo.toml
    │   └── src/main.rs
    └── detector-userspace/
        ├── Cargo.toml
        ├── build.rs
        └── src/main.rs
```

### Verantwortlichkeiten

- **`detector-common`:** `no_std`-fähige Draht-ABI mit `#[repr(C)]`, festen Integern, `bytemuck::Pod`, Event-Header, ABI-Version und Compile-Time-Größenassertions.
- **`detector-ebpf`:** Aya-eBPF-Programme für Tracepoints. Das Programm kopiert nur begrenzte Metadaten; keine dynamischen Rust-Allokationen und keine Kernel- oder Userspace-Pointer werden in Events ausgegeben.
- **`detector-userspace`:** Aya Loader, Layout-Preflight über tracefs, Tokio `AsyncFd` Ring-Buffer-Reader, Parser mit exakter ABI-Längenprüfung, Prozess-Korrelation, Heuristiken und JSON-Logs.

Aya ist für diesen Workspace auf `aya = 0.14.0`, `aya-ebpf = 0.2.1` und `aya-build = 0.2.1` festgelegt. Das Build-Skript pinnt `bpf-linker` auf `0.12.0`. Für reproduzierbare Dependency-Auflösung muss die beim ersten Cargo-Build erzeugte `Cargo.lock` mit ins Repository committed werden.

## Erfasste Signale

| Probe | Signal | Interpretation |
|---|---|---|
| `syscalls:sys_enter_execve` | PID/TID, UID/GID, `comm`, Pfad, bis zu vier Argumente | `execve`-Versuch, noch kein Erfolgsbeweis |
| `syscalls:sys_enter_execveat` | Pfad und begrenzte Argumente aus den generischen Syscall-Argumenten | `execveat`-Versuch; `dirfd` und `at_flags` werden derzeit nicht in der ABI gespeichert |
| `syscalls:sys_exit_execve` / `sys_exit_execveat` | Rückgabewert und errno bei Rückkehr | protokolliert fehlgeschlagene Exec-Syscalls; erfolgreiche Image-Wechsel werden separat bestätigt |
| `sched:sched_process_exec` | erfolgreicher Image-Wechsel, PID/TID, `old_pid`, `comm` | Kernel bestätigt erfolgreiches Exec; wird anhand `old_pid` auch bei TID-Wechseln korreliert |
| `sched:sched_process_fork` | Parent-/Child-TID und `comm` | kurzfristiger Parent-Child-Kontext |
| `sched:sched_process_exit` | Task-Ende | entfernt Korrelationszustand |
| `syscalls:sys_enter/exit_init_module` | `init_module`-Versuch und Rückgabewert | Erfolg wird anhand des Syscall-Exit beurteilt |
| `syscalls:sys_enter/exit_finit_module` | `finit_module`-Versuch und Rückgabewert | Erfolg wird anhand des Syscall-Exit beurteilt |
| `module:module_load` | Kernel-Modul ist geladen, Taint-Bits, `comm` | unabhängiges Erfolgsereignis des Kernel-Tracepoints |
| `syscalls:sys_enter/exit_getdents64` | FD, angeforderte und zurückgegebene Bytezahl | Verzeichnis-Enumeration-Metadaten, kein Inhaltsscan |

### ABI und Datenverlust

Jedes Event beginnt mit einem 16-Byte-`EventHeader`. ABI-Version, Event-Typ, Flags und monotonic Kernel-Timestamp werden vor der Event-spezifischen Dekodierung geprüft. Änderungen an den Structs erfordern eine Erhöhung von `ABI_VERSION`.

Der Ring-Buffer ist global und 16 MiB groß. Er ermöglicht CPU-übergreifende Event-Reihenfolge; bei fehlendem freien Platz kann eine Reservierung dennoch fehlschlagen. Daher gibt es zwei `PerCpuArray`-Zähler:

- `LOST_EVENTS`: Ein Event konnte wegen nicht verfügbarer Ring-Buffer-Kapazität nicht reserviert werden.
- `PROBE_ERRORS`: Ein Probe konnte einen benötigten Wert aus dem Tracepoint-Kontext nicht lesen.

Der Daemon summiert beide Zähler alle fünf Sekunden und gibt Deltas als strukturierte Warnungen aus. `PROBE_ERRORS` umfasst Tracepoint-Lese- und `comm`-Helper-Fehler; User-Pointer-Lesefehler der Exec-Probe werden direkt am jeweiligen Event markiert. Parent-, Exec-, Modul- und Verzeichnis-Korrelationszustände haben harte Größenlimits und monotone TTL-Ablaufzeiten; abgelaufene Einträge werden regelmäßig entfernt. Bei Cache-Druck werden in begrenzten Batches die ältesten Korrelationen entfernt, statt den gesamten Kontext zu löschen. Das ist Verlusttransparenz, keine Zero-Drop-Garantie. <https://docs.rs/aya/0.14.0/aya/maps/ring_buf/struct.RingBuf.html>

## Detektionslogik und Grenzen

1. **Exec-Korrelation:** `sys_enter_execve` und `sys_enter_execveat` protokollieren den Versuch. Fehlgeschlagene Syscalls werden am jeweiligen `sys_exit` mit errno sichtbar; `sched_process_exec` bestätigt erfolgreiche Image-Wechsel. Für Execs aus Nicht-Leader-Threads wird `old_pid` zur Korrelation verwendet. Wenn das Entry-Event wegen Buffer-Druck fehlt, bleibt das Erfolgsereignis als `unpaired` sichtbar.
2. **Parent-Child-Heuristik:** Ein Root-Prozess, der aus `/tmp`, `/var/tmp` oder `/dev/shm` startet und dessen beobachteter Parent ein Shell-/Interpreter-Prozess ist, erhält einen heuristischen Alarm. Das ist ein Signal mit möglicher False-Positive-Rate, keine Rootkit-Feststellung.
3. **Kernel-Module:** Syscall-Entry/Exit zeigt Versuche und Return-Code. `module:module_load` liefert ein separates Kernel-Erfolgsereignis und Taint-Metadaten. Die Modulnamen werden in dieser ABI-Version absichtlich noch nicht aus dem dynamischen `data_loc`-Feld ausgelesen. Das `module_load`-Event wird über die TID mit einem noch offenen `init_module`-/`finit_module`-Versuch korreliert, sofern beide Events beobachtet wurden.
4. **`getdents64`:** Erfasst FD, angeforderte Puffergröße und Rückgabegröße. Eine Rückgabe größer als der angeforderte Puffer wird als Integritätsanomalie markiert. Das Event liest keine `dirent`-Namen und kann für sich allein keine versteckten Dateien beweisen.
5. **DKOM:** Es gibt noch keine unabhängige Task- oder Dateisystem-Inventarisierung. Belastbare Hidden-Process-Erkennung erfordert eine zweite Kernel-Sicht, etwa BTF-/CO-RE-basierte Task-Enumeration, sowie Namespace-, Race- und False-Positive-Behandlung. Ein Userspace-`ps`/`/proc`-Vergleich allein ist keine unabhängige Wahrheit, wenn der Kernel kompromittiert ist.
6. **Datenschutz:** Argumente können Geheimnisse enthalten. Die Userspace-Redaktion maskiert einige verbreitete `--password`-/`--token`-/`secret=`-Muster, ist aber keine vollständige DLP-Policy. Vor dem Produktivbetrieb müssen Redaktionsregeln, Aufbewahrung und Log-Zugriff festgelegt werden.

## Voraussetzungen

Zielbaseline: Ubuntu 24.04 LTS x86_64 mit Kernel 6.8 oder ein Kernel, dessen Tracepoint-Felder exakt den unterstützten Layouts entsprechen.

- Linux Kernel **>= 5.8** (BPF Ring Buffer).
- Tracefs unter `/sys/kernel/tracing` oder `/sys/kernel/debug/tracing`.
- Kernel-Tracepoints für `syscalls`, `sched` und `module`; `CONFIG_MODULES` für Modul-Ladeereignisse.
- Rust stable und Rust nightly mit `rust-src`.
- `clang`, `llvm-ar`, `pkg-config`, `libelf-dev`, `build-essential`.
- Root für den Lab-Start oder ein eng zugeschnittenes, kernel- und distributionsabhängiges Capability-Setup.

BTF ist für die derzeitigen festen Tracepoint-Probes nicht zwingend erforderlich. Es wird für zukünftige BTF-/CO-RE-basierte unabhängige Kernel-Inventarisierung benötigt bzw. dringend empfohlen.

## Installation und Build auf Ubuntu 24.04

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libelf-dev clang llvm git kmod

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cd ebpf-detector
./scripts/build.sh
```

Das Skript prüft die Linux-Umgebung und Native-Tools, installiert stable sowie nightly mit `rust-src`, installiert `bpf-linker 0.12.0` und baut `detector-userspace`. Der `build.rs`-Schritt verwendet `aya-build`, kompiliert `detector-ebpf` für BPF und bettet das resultierende ELF in den Daemon ein.

Zum Start:

```bash
sudo RUST_LOG=info ./target/release/detector-userspace
```

Mehr Details:

```bash
sudo RUST_LOG=debug ./target/release/detector-userspace
```

Vor dem Attach prüft der Loader für alle 14 Tracepoints die erwarteten Feldnamen, Offsets und Größen anhand ihrer `format`-Dateien. Ein unbekanntes Layout führt absichtlich zum Abbruch. Tracepoint-Formate sind die vom Kernel bereitgestellte Beschreibung des Event-Records. <https://docs.kernel.org/trace/events.html>

Falls tracefs nicht gemountet ist:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

## Smoke-Test (Lab-VM empfohlen)

Terminal 1:

```bash
sudo RUST_LOG=debug ./target/release/detector-userspace
```

Terminal 2:

```bash
sudo ./scripts/smoke-test.sh
```

Der Test führt normale Programme aus, traversiert `/etc`, startet `/usr/bin/true` aus einem temporären Verzeichnis unter Root und versucht mit `insmod` eine ungültige Textdatei als Modul zu laden. Er lädt **kein echtes Kernelmodul** und ändert keine Kernelparameter.

Erwartete strukturierte Ereignisse:

- `exec_attempt` plus `process_exec` für erfolgreiche Prozessstarts.
- `exec_failure` für den absichtlich fehlgeschlagenen `execve`-Aufruf.
- `directory_enum` auf DEBUG-Level.
- `root_exec_from_writable_path` oder `root_child_exec_from_writable_path` für den absichtlich ungewöhnlichen Root-Start aus `/tmp`.
- `module_syscall_attempt` und ein fehlgeschlagenes `module_syscall_result`, falls `insmod` installiert ist.
- Ein `module_load`-Event erscheint nur bei einem tatsächlich erfolgreichen Kernel-Modulladevorgang; der Smoke-Test führt absichtlich keinen solchen Ladevorgang durch.

Für einen echten `module_load`-Integrationstest ausschließlich eine vertrauenswürdige, signierte Testmoduldatei in einer wegwerfbaren VM verwenden.

## systemd-Deployment (optional)

Nach erfolgreichem Lab-Test:

```bash
sudo install -D -m 0755 target/release/detector-userspace /usr/local/sbin/detector-userspace
sudo install -D -m 0644 deploy/detector.service /etc/systemd/system/detector.service
sudo systemctl daemon-reload
sudo systemctl enable --now detector.service
sudo journalctl -u detector.service -f
```

Die Unit enthält ein Capability-Bounding-Set. `CAP_SYS_ADMIN` ist als Kompatibilitäts-Fallback enthalten und sollte nach Prüfung auf dem Zielkernel entfernt werden, falls `CAP_BPF`, `CAP_PERFMON` und `CAP_SYS_RESOURCE` ausreichen. Vor einem produktiven Rollout sind insbesondere Capability-Bedarf, Kernel-Lockdown, LSM-Regeln, Dienstisolation und Log-Retention auf der konkreten Distribution zu validieren.

## Qualitätssicherung

```bash
cargo +stable fmt --all -- --check
cargo +stable test -p detector-common -p detector-userspace
cargo +stable clippy -p detector-common -p detector-userspace --all-targets -- -D warnings
```

GitHub Actions führt Format-, Build-, Test- und Clippy-Schritte auf Ubuntu 24.04 aus. Die Tests enthalten ABI-Größenassertions und Unit-Tests für Tracepoint-Format-Parsing sowie die Shell-Heuristik. Der BPF-Verifier-Test muss zusätzlich auf jeder unterstützten Kernelversion in einer VM laufen.

## Security-Hardening-Backlog

- BTF-/CO-RE-gestützte Task-Inventarisierung und unabhängige Prozess-Sicht für DKOM-Signale.
- VFS-/Mount-Namespace-kontextualisierte Datei-Integritätsprüfung; `getdents64`-Metadaten allein reichen nicht.
- Modulname/Signatur-/Hash-Anreicherung und Abgleich mit `module_load`, `module_free` sowie Kernel-Trust-Policy.
- `execveat`-Erweiterung um `dirfd` / `at_flags` sowie zusätzliche Prozessattribut-Korrelation.
- Begrenzte, expiry-basierte User-Space-Caches und Metriken für Event-Latenz/Queue-Pressure.
- Konfigurierbare Allow-/Deny-Policies, Datenminimierung und vollständige Secret-Redaktion.
- Integrationstests unter Kernel 6.8, 6.11+, HWE-Kernels sowie ARM64, sofern diese Targets freigegeben werden.
- Release-Signing, SBOM, Dependency-Audit, reproducible build pipeline und Kernel-Verifier-Regressionstests.
