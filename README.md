# eBPF Detector — Rust + Aya

A Linux kernel telemetry and detection sensor written in Rust. The current implementation captures `execve` and `execveat` activity (including failed syscalls and confirmed image replacement), fork/exit relationships, kernel module loading attempts and confirmed module-load events, and `getdents64` metadata. Events flow from a shared BPF ring buffer into an asynchronous Tokio daemon.

> **Maturity level:** Security-research / portfolio prototype. This project is not a certified EDR and is not yet a complete rootkit or DKOM detector. It does not modify kernel structures and does not attempt to actively remove rootkits.

## Architecture

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
    U --> V[ABI / length / version validation]
    V --> H[Process and module correlation]
    H --> J[JSON logs via tracing]
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

### Responsibilities

- **`detector-common`:** `no_std`-capable wire ABI using `#[repr(C)]`, fixed-size integers, `bytemuck::Pod`, event headers, ABI versioning, and compile-time size assertions.
- **`detector-ebpf`:** Aya eBPF programs for tracepoints. The program copies only bounded metadata; no dynamic Rust allocations and no kernel or userspace pointers are emitted in events.
- **`detector-userspace`:** Aya loader, tracefs layout preflight, Tokio `AsyncFd` ring-buffer reader, parser with strict ABI length checks, process correlation, heuristics, and JSON logging.

Aya is pinned for this workspace to `aya = 0.14.0`, `aya-ebpf = 0.2.1`, and `aya-build = 0.2.1`. The build script pins `bpf-linker` to `0.12.0`. For reproducible dependency resolution, the `Cargo.lock` generated during the first Cargo build should be committed to the repository.

## Captured Signals

| Probe | Signal | Interpretation |
|---|---|---|
| `syscalls:sys_enter_execve` | PID/TID, UID/GID, `comm`, path, up to four arguments | `execve` attempt; no success proof yet |
| `syscalls:sys_enter_execveat` | Path and bounded arguments from generic syscall arguments | `execveat` attempt; `dirfd` and `at_flags` are not currently stored in the ABI |
| `syscalls:sys_exit_execve` / `sys_exit_execveat` | Return value and errno upon return | Logs failed exec syscalls; successful image replacement is confirmed separately |
| `sched:sched_process_exec` | successful image replacement, PID/TID, `old_pid`, `comm` | Kernel confirms successful exec; correlated by `old_pid` even when TIDs change |
| `sched:sched_process_fork` | parent/child TID and `comm` | short-lived parent-child context |
| `sched:sched_process_exit` | task exit | clears correlation state |
| `syscalls:sys_enter/exit_init_module` | `init_module` attempt and return value | success determined from syscall exit |
| `syscalls:sys_enter/exit_finit_module` | `finit_module` attempt and return value | success determined from syscall exit |
| `module:module_load` | kernel module loaded, taint bits, `comm` | separate successful kernel tracepoint event |
| `syscalls:sys_enter/exit_getdents64` | FD, requested and returned byte count | directory enumeration metadata; not a content scan |

### ABI and Data Loss

Each event begins with a 16-byte `EventHeader`. ABI version, event type, flags, and the monotonic kernel timestamp are validated before event-specific decoding. Any change to the structs requires increasing `ABI_VERSION`.

The ring buffer is global and 16 MiB in size. It allows CPU-crossing event ordering; if capacity is exhausted, a reservation may still fail. For this reason, there are two `PerCpuArray` counters:

- `LOST_EVENTS`: An event could not be reserved because the ring buffer had no available capacity.
- `PROBE_ERRORS`: A probe could not read a required value from the tracepoint context.

The daemon sums both counters every five seconds and emits deltas as structured warnings. `PROBE_ERRORS` includes tracepoint read and `comm` helper failures; user-pointer read errors from the exec probe are flagged directly on the event itself. Parent, exec, module, and directory correlation state each have hard size limits and monotonic TTL expirations; expired entries are regularly removed. Under cache pressure, the oldest correlations are evicted in bounded batches rather than dropping the entire context. This is loss transparency, not a zero-drop guarantee. <https://docs.rs/aya/0.14.0/aya/maps/ring_buf/struct.RingBuf.html>

## Detection Logic and Limits

1. **Exec correlation:** `sys_enter_execve` and `sys_enter_execveat` record the attempt. Failed syscalls become visible at the matching `sys_exit` with errno; `sched_process_exec` confirms successful image replacements. For execs from non-leader threads, `old_pid` is used for correlation. If the entry event is missing due to buffer pressure, the success event remains visible as `unpaired`.
2. **Parent-child heuristic:** A root process launched from `/tmp`, `/var/tmp`, or `/dev/shm` whose observed parent is a shell or interpreter process produces a heuristic alert. This is an indicator with a possible false-positive rate, not a rootkit finding.
3. **Kernel modules:** Syscall entry/exit shows attempts and return codes. `module:module_load` produces a separate kernel success event and taint metadata. Module names are intentionally not extracted from the dynamic `data_loc` field in this ABI version. The `module_load` event is correlated by TID with an open `init_module` / `finit_module` attempt when both events are observed.
4. **`getdents64`:** Captures FD, requested buffer size, and returned size. A return value larger than the requested buffer is flagged as an integrity anomaly. The event does not read `dirent` names and cannot prove hidden files by itself.
5. **DKOM:** There is still no independent task or filesystem inventory. Robust hidden-process detection requires a second kernel view, such as BTF/CO-RE-based task enumeration, plus namespace, race, and false-positive handling. A userspace `ps` / `/proc` comparison alone is not independent truth when the kernel may be compromised.
6. **Privacy:** Arguments may contain secrets. Userspace redaction masks common `--password` / `--token` / `secret=` patterns, but it is not a complete DLP policy. Before production deployment, redaction rules, retention policy, and log access controls must be defined.

## Requirements

Target baseline: Ubuntu 24.04 LTS x86_64 with Linux 6.8 or a kernel whose tracepoint fields exactly match the supported layouts.

- Linux kernel **>= 5.8** (BPF ring buffer).
- Tracefs mounted at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`.
- Tracepoints for `syscalls`, `sched`, and `module`; `CONFIG_MODULES` for module-load events.
- Rust stable and Rust nightly with `rust-src`.
- `clang`, `llvm-ar`, `pkg-config`, `libelf-dev`, and `build-essential`.
- Root for lab startup or a tightly scoped, kernel- and distribution-dependent capability setup.

BTF is not required for the current fixed tracepoint probes. It is needed or strongly recommended for future BTF/CO-RE-based independent kernel inventorying.

## Installation and Build on Ubuntu 24.04

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libelf-dev clang llvm git kmod

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

cd ebpf-detector
./scripts/build.sh
```

The script checks the Linux environment and native tools, installs stable and nightly with `rust-src`, installs `bpf-linker 0.12.0`, and builds `detector-userspace`. The `build.rs` step uses `aya-build`, compiles `detector-ebpf` for BPF, and embeds the resulting ELF into the daemon.

To start:

```bash
sudo RUST_LOG=info ./target/release/detector-userspace
```

For more details:

```bash
sudo RUST_LOG=debug ./target/release/detector-userspace
```

Before attaching, the loader validates all 14 tracepoints for the expected field names, offsets, and sizes using their `format` files. An unknown layout intentionally aborts the load. Tracepoint formats are the kernel-provided description of the event record. <https://docs.kernel.org/trace/events.html>

If tracefs is not mounted:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

## Smoke Test (lab VM recommended)

Terminal 1:

```bash
sudo RUST_LOG=debug ./target/release/detector-userspace
```

Terminal 2:

```bash
sudo ./scripts/smoke-test.sh
```

The test runs normal programs, traverses `/etc`, starts `/usr/bin/true` from a temporary directory under root, and attempts to load an invalid text file as a module using `insmod`. It does not load a real kernel module and does not modify kernel parameters.

Expected structured events:

- `exec_attempt` plus `process_exec` for successful process starts.
- `exec_failure` for the intentionally failed `execve` call.
- `directory_enum` at DEBUG level.
- `root_exec_from_writable_path` or `root_child_exec_from_writable_path` for the intentionally unusual root launch from `/tmp`.
- `module_syscall_attempt` and a failed `module_syscall_result` if `insmod` is installed.
- A `module_load` event appears only during an actual successful kernel module load. The smoke test deliberately does not perform such a load.

For a real `module_load` integration test, use a trusted, signed test module in a disposable VM only.

## systemd Deployment (optional)

After successful lab testing:

```bash
sudo install -D -m 0755 target/release/detector-userspace /usr/local/sbin/detector-userspace
sudo install -D -m 0644 deploy/detector.service /etc/systemd/system/detector.service
sudo systemctl daemon-reload
sudo systemctl enable --now detector.service
sudo journalctl -u detector.service -f
```

The unit includes a capability bounding set. `CAP_SYS_ADMIN` is present as a compatibility fallback and should be removed after validation on the target kernel if `CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_RESOURCE` are sufficient. Before production rollout, capability requirements, kernel lockdown, LSM policies, service isolation, and log retention must be validated for the specific distribution.

## Quality Assurance

```bash
cargo +stable fmt --all -- --check
cargo +stable test -p detector-common -p detector-userspace
cargo +stable clippy -p detector-common -p detector-userspace --all-targets -- -D warnings
```

GitHub Actions runs format, build, test, and Clippy steps on Ubuntu 24.04. The tests include ABI size assertions and unit tests for tracepoint format parsing and shell heuristics. The BPF verifier test must also run on every supported kernel version in a VM.

## Security Hardening Backlog

- BTF/CO-RE-based task inventory and independent process visibility for DKOM signals.
- VFS/mount-namespace contextual file-integrity checks; `getdents64` metadata alone is insufficient.
- Module name/signature/hash enrichment and comparison against `module_load`, `module_free`, and kernel trust policy.
- `execveat` extension to include `dirfd` / `at_flags` and extra process-attribute correlation.
- Bounded, expiry-based userspace caches and metrics for event latency and queue pressure.
- Configurable allow/deny policies, data minimization, and full secret redaction.
- Integration tests under kernel 6.8, 6.11+, HWE kernels, and ARM64 if those targets are supported.
- Release signing, SBOM, dependency audit, reproducible build pipeline, and kernel verifier regression tests.
