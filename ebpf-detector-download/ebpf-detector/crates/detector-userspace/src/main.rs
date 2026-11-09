use std::{
    collections::HashMap,
    fs,
    mem::size_of,
    path::Path,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use aya::{
    EbpfLoader,
    maps::{PerCpuArray, RingBuf},
    programs::TracePoint,
};
use bytemuck::try_pod_read_unaligned;
use detector_common::{
    ABI_VERSION, DirectoryReadEnterEvent, DirectoryReadExitEvent, EVENT_EXEC_ATTEMPT,
    EVENT_EXEC_RESULT,
    EVENT_GETDENTS_ENTER, EVENT_GETDENTS_EXIT, EVENT_MODULE_LOAD, EVENT_MODULE_SYSCALL_ENTER,
    EVENT_MODULE_SYSCALL_EXIT, EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT, EVENT_PROCESS_FORK,
    EXEC_ARG_SLOT_LEN, EXEC_ARG_SLOTS, EventHeader, ExecAttemptResultEvent, ExecEvent,
    EXEC_OP_EXECVE, EXEC_OP_EXECVEAT, FLAG_EXECVEAT, FLAG_ARGS_READ_FAILED,
    FLAG_ARGS_TRUNCATED,
    FLAG_COMM_READ_FAILED, FLAG_PATH_READ_FAILED, FLAG_PATH_TRUNCATED,
    FLAG_SYSCALL_ARGS_READ_FAILED, ModuleSyscallEvent, ModuleSyscallResultEvent,
    MODULE_OP_FINIT_MODULE, MODULE_OP_INIT_MODULE, ModuleLoadEvent, ProcessExecEvent,
    ProcessExitEvent, ProcessForkEvent,
};
use tokio::{
    io::unix::AsyncFd,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

const EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/detector-ebpf"));
const MAX_BATCH: usize = 4096;
const MAX_TRACKED_TASKS: usize = 65_536;
const MAX_PENDING_DIR_READS: usize = 8_192;
const MAX_PENDING_EXEC_ATTEMPTS: usize = 16_384;
const MAX_PENDING_MODULE_ATTEMPTS: usize = 4_096;
const CACHE_EVICT_BATCH: usize = 256;
const PARENT_CONTEXT_TTL: Duration = Duration::from_secs(60);
const EXEC_ATTEMPT_TTL: Duration = Duration::from_secs(10);
const DIRECTORY_READ_TTL: Duration = Duration::from_secs(30);
const MODULE_ATTEMPT_TTL: Duration = Duration::from_secs(10);

const TRACEPOINT_LAYOUTS: &[(&str, &[(&str, usize, usize)])] = &[
    ("syscalls/sys_enter_execve", &[("filename", 16, 8), ("argv", 24, 8)]),
    ("syscalls/sys_exit_execve", &[("ret", 16, 8)]),
    ("syscalls/sys_enter_execveat", &[("args", 16, 48)]),
    ("syscalls/sys_exit_execveat", &[("ret", 16, 8)]),
    ("syscalls/sys_enter_init_module", &[("args", 16, 48)]),
    ("syscalls/sys_exit_init_module", &[("ret", 16, 8)]),
    ("syscalls/sys_enter_finit_module", &[("args", 16, 48)]),
    ("syscalls/sys_exit_finit_module", &[("ret", 16, 8)]),
    ("syscalls/sys_enter_getdents64", &[("args", 16, 48)]),
    ("syscalls/sys_exit_getdents64", &[("ret", 16, 8)]),
    (
        "sched/sched_process_fork",
        &[
            ("parent_comm", 8, 16),
            ("parent_pid", 24, 4),
            ("child_comm", 28, 16),
            ("child_pid", 44, 4),
        ],
    ),
    ("sched/sched_process_exit", &[("comm", 8, 16), ("pid", 24, 4)]),
    ("sched/sched_process_exec", &[("old_pid", 16, 4)]),
    ("module/module_load", &[("taints", 8, 4)]),
];

#[derive(Clone, Debug)]
struct ParentContext {
    parent_tid: u32,
    parent_comm: String,
    observed_at: Instant,
}

#[derive(Clone, Debug)]
struct ExecAttemptContext {
    observed_at: Instant,
    filename: String,
    operation: u32,
}

#[derive(Clone, Debug)]
struct DirectoryReadContext {
    dirfd: i32,
    requested_bytes: u32,
    enter_timestamp_ns: u64,
    observed_at: Instant,
}

#[derive(Debug)]
struct ModuleAttemptContext {
    operation: u32,
    observed_at: Instant,
}

#[derive(Default)]
struct CorrelationState {
    parent_by_child_tid: HashMap<u32, ParentContext>,
    exec_attempts_by_tid: HashMap<u32, ExecAttemptContext>,
    directory_reads_by_tid: HashMap<u32, DirectoryReadContext>,
    module_attempts_by_tid: HashMap<u32, ModuleAttemptContext>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    check_tracepoint_layout().context("Tracepoint-ABI-Prüfung fehlgeschlagen")?;

    info!(component = "loader", "Lade eBPF-Objekt");
    let mut ebpf = EbpfLoader::new()
        .load(EBPF_OBJECT)
        .context("Aya konnte das eBPF-Objekt nicht laden; Kernel/BTF/Rechte prüfen")?;

    attach_tracepoint(&mut ebpf, "execve_enter", "syscalls", "sys_enter_execve")?;
    attach_tracepoint(&mut ebpf, "execve_exit", "syscalls", "sys_exit_execve")?;
    attach_tracepoint(&mut ebpf, "execveat_enter", "syscalls", "sys_enter_execveat")?;
    attach_tracepoint(&mut ebpf, "execveat_exit", "syscalls", "sys_exit_execveat")?;
    attach_tracepoint(&mut ebpf, "process_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut ebpf, "process_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "process_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut ebpf, "module_load", "module", "module_load")?;
    attach_tracepoint(&mut ebpf, "init_module_enter", "syscalls", "sys_enter_init_module")?;
    attach_tracepoint(&mut ebpf, "init_module_exit", "syscalls", "sys_exit_init_module")?;
    attach_tracepoint(&mut ebpf, "finit_module_enter", "syscalls", "sys_enter_finit_module")?;
    attach_tracepoint(&mut ebpf, "finit_module_exit", "syscalls", "sys_exit_finit_module")?;
    attach_tracepoint(&mut ebpf, "getdents_enter", "syscalls", "sys_enter_getdents64")?;
    attach_tracepoint(&mut ebpf, "getdents_exit", "syscalls", "sys_exit_getdents64")?;

    // Take ownership of the maps so the async ring reader and metrics reader
    // can coexist without holding overlapping mutable borrows of `Ebpf`.
    let ring_map = ebpf.take_map("EVENTS").context("eBPF-Map EVENTS fehlt")?;
    let ring_buf = RingBuf::try_from(ring_map).context("EVENTS ist kein RingBuf")?;
    let mut ring = AsyncFd::new(ring_buf)
        .context("Tokio AsyncFd für den BPF-Ring-Buffer konnte nicht initialisiert werden")?;

    let lost_map = ebpf
        .take_map("LOST_EVENTS")
        .context("eBPF-Map LOST_EVENTS fehlt")?;
    let lost_events = PerCpuArray::<_, u64>::try_from(lost_map)
        .context("LOST_EVENTS ist keine PerCpuArray<u64>")?;
    let probe_error_map = ebpf
        .take_map("PROBE_ERRORS")
        .context("eBPF-Map PROBE_ERRORS fehlt")?;
    let probe_errors = PerCpuArray::<_, u64>::try_from(probe_error_map)
        .context("PROBE_ERRORS ist keine PerCpuArray<u64>")?;

    info!(
        ring_buffer_bytes = 1 << 24,
        probes = 14,
        "Kernel-Sensor aktiv; warte auf Events"
    );

    let mut state = CorrelationState::default();
    let mut drop_poll = time::interval(Duration::from_secs(5));
    drop_poll.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Consume the interval's immediate first tick; first report is after 5 s.
    drop_poll.tick().await;
    let mut previous_drops = 0u64;
    let mut previous_probe_errors = 0u64;

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            signal_result = &mut shutdown => {
                signal_result.context("Ctrl-C-Signal konnte nicht verarbeitet werden")?;
                info!("Shutdown angefordert");
                break;
            }
            _ = drop_poll.tick() => {
                match read_counter_total(&lost_events) {
                    Ok(total) => {
                        let delta = total.saturating_sub(previous_drops);
                        if delta > 0 {
                            warn!(
                                event = "telemetry_loss",
                                total_lost_events = total,
                                lost_since_last_report = delta,
                                "BPF-Ring-Buffer hat Events nicht reservieren können"
                            );
                        } else {
                            debug!(total_lost_events = total, "BPF-Drop-Counter gelesen");
                        }
                        previous_drops = total;
                    }
                    Err(error) => warn!(%error, "Drop-Counter konnte nicht gelesen werden"),
                }
                prune_stale_correlations(&mut state);
                match read_counter_total(&probe_errors) {
                    Ok(total) => {
                        let delta = total.saturating_sub(previous_probe_errors);
                        if delta > 0 {
                            warn!(
                                event = "probe_errors",
                                total_probe_errors = total,
                                probe_errors_since_last_report = delta,
                                "BPF-Probe konnte Tracepoint-Kontext nicht vollständig lesen"
                            );
                        }
                        previous_probe_errors = total;
                    }
                    Err(error) => warn!(%error, "Probe-Fehlerzähler konnte nicht gelesen werden"),
                }
            }
            readiness = ring.readable_mut() => {
                let mut guard = readiness.context("Ring-Buffer Readiness fehlgeschlagen")?;
                let mut drained = 0usize;
                loop {
                    match guard.get_inner_mut().next() {
                        Some(item) => {
                            handle_raw_event(&item, &mut state);
                            drained += 1;
                            if drained >= MAX_BATCH {
                                break;
                            }
                        }
                        None => {
                            guard.clear_ready();
                            break;
                        }
                    }
                }
                debug!(drained, "Ring-Buffer-Batch verarbeitet");
            }
        }
    }

    info!("Sensor heruntergefahren");
    Ok(())
}

fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    tracepoint: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("eBPF-Programm {program_name} fehlt im ELF"))?
        .try_into()
        .with_context(|| format!("{program_name} ist kein Aya-TracePoint-Programm"))?;
    program
        .load()
        .with_context(|| format!("Kernel hat {program_name} abgelehnt; Verifier-Log prüfen"))?;
    program
        .attach(category, tracepoint)
        .with_context(|| format!("Attach an {category}:{tracepoint} fehlgeschlagen"))?;
    info!(program = program_name, category, tracepoint, "Tracepoint attached");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,aya=warn"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .init();
}

fn tracepoint_format_path(relative: &str) -> anyhow::Result<std::path::PathBuf> {
    let candidates = [
        Path::new("/sys/kernel/tracing/events").join(relative).join("format"),
        Path::new("/sys/kernel/debug/tracing/events").join(relative).join("format"),
    ];
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("Tracepoint-Format {relative} nicht gefunden; tracefs mounten"))
}

/// Fail closed unless the active kernel tracepoint record layout matches the
/// explicitly supported Ubuntu 24.04 / Linux 6.8 baseline.
fn check_tracepoint_layout() -> anyhow::Result<()> {
    for &(tracepoint, expected_fields) in TRACEPOINT_LAYOUTS {
        let format_path = tracepoint_format_path(tracepoint)?;
        let format = fs::read_to_string(&format_path)
            .with_context(|| format!("Tracepoint-Format {} nicht lesbar", format_path.display()))?;
        for &(field, expected_offset, expected_size) in expected_fields {
            let (actual_offset, actual_size) = tracepoint_field_layout(&format, field)
                .with_context(|| format!("{tracepoint}: Feld {field} nicht gefunden"))?;
            if actual_offset != expected_offset || actual_size != expected_size {
                bail!(
                    "Nicht unterstütztes Layout für {tracepoint}.{field}: Offset/Size {actual_offset}/{actual_size}, erwartet {expected_offset}/{expected_size}"
                );
            }
        }
        info!(tracepoint, "Tracepoint-Layout verifiziert");
    }
    Ok(())
}

fn tracepoint_field_layout(format: &str, expected_name: &str) -> anyhow::Result<(usize, usize)> {
    for line in format.lines() {
        let Some(declaration) = line
            .strip_prefix("field:")
            .and_then(|rest| rest.split(';').next())
        else {
            continue;
        };
        let Some(raw_name) = declaration.split_whitespace().last() else {
            continue;
        };
        let actual_name = raw_name.split('[').next().unwrap_or(raw_name);
        if actual_name == expected_name {
            let raw_offset = line
                .split("offset:")
                .nth(1)
                .context("offset-Feld fehlt im Tracepoint-Format")?
                .split(';')
                .next()
                .context("offset-Wert ist leer")?
                .trim();
            let offset = raw_offset
                .parse::<usize>()
                .with_context(|| format!("Ungültiger Offset für {expected_name}"))?;
            let raw_size = line
                .split("size:")
                .nth(1)
                .context("size-Feld fehlt im Tracepoint-Format")?
                .split(';')
                .next()
                .context("size-Wert ist leer")?
                .trim();
            let size = raw_size
                .parse::<usize>()
                .with_context(|| format!("Ungültige Größe für {expected_name}"))?;
            return Ok((offset, size));
        }
    }
    bail!("Tracepoint-Feld {expected_name} nicht gefunden")
}

fn read_counter_total(map: &PerCpuArray<aya::maps::MapData, u64>) -> anyhow::Result<u64> {
    let per_cpu = map.get(&0, 0).context("Per-CPU-Counter nicht lesbar")?;
    Ok(per_cpu.iter().copied().fold(0u64, u64::saturating_add))
}

fn handle_raw_event(raw: &[u8], state: &mut CorrelationState) {
    if raw.len() < size_of::<EventHeader>() {
        warn!(received_len = raw.len(), "Zu kleines Event verworfen");
        return;
    }
    let header = match try_pod_read_unaligned::<EventHeader>(&raw[..size_of::<EventHeader>()]) {
        Ok(header) => header,
        Err(error) => {
            warn!(%error, "Event-Header konnte nicht dekodiert werden");
            return;
        }
    };
    if header.abi_version != ABI_VERSION {
        warn!(received_version = header.abi_version, expected_version = ABI_VERSION, "Event mit inkompatibler ABI-Version verworfen");
        return;
    }

    match header.event_type {
        EVENT_EXEC_ATTEMPT => decode_event::<ExecEvent>(raw, report_exec_attempt, state),
        EVENT_EXEC_RESULT => decode_event::<ExecAttemptResultEvent>(raw, report_exec_result, state),
        EVENT_MODULE_SYSCALL_ENTER => decode_event::<ModuleSyscallEvent>(raw, report_module_enter, state),
        EVENT_MODULE_SYSCALL_EXIT => decode_event::<ModuleSyscallResultEvent>(raw, report_module_exit, state),
        EVENT_GETDENTS_ENTER => decode_event::<DirectoryReadEnterEvent>(raw, report_getdents_enter, state),
        EVENT_GETDENTS_EXIT => decode_event::<DirectoryReadExitEvent>(raw, report_getdents_exit, state),
        EVENT_PROCESS_FORK => decode_event::<ProcessForkEvent>(raw, report_process_fork, state),
        EVENT_PROCESS_EXIT => decode_event::<ProcessExitEvent>(raw, report_process_exit, state),
        EVENT_PROCESS_EXEC => decode_event::<ProcessExecEvent>(raw, report_process_exec, state),
        EVENT_MODULE_LOAD => decode_event::<ModuleLoadEvent>(raw, report_module_load, state),
        other => warn!(event_type = other, "Unbekannter Event-Typ verworfen"),
    }
}

fn decode_event<T: bytemuck::Pod>(
    raw: &[u8],
    handler: fn(&T, &mut CorrelationState),
    state: &mut CorrelationState,
) {
    if raw.len() != size_of::<T>() {
        warn!(received_len = raw.len(), expected_len = size_of::<T>(), "Event mit falscher ABI-Größe verworfen");
        return;
    }
    match try_pod_read_unaligned::<T>(raw) {
        Ok(event) => handler(&event, state),
        Err(error) => warn!(%error, "Event konnte nicht dekodiert werden"),
    }
}

fn report_exec_attempt(event: &ExecEvent, state: &mut CorrelationState) {
    let comm = c_array_to_string(&event.comm);
    let filename = c_array_to_string(&event.filename);
    let argv = format_argv(event);
    let operation = if event.header.flags & FLAG_EXECVEAT != 0 {
        exec_operation_name(EXEC_OP_EXECVEAT)
    } else {
        exec_operation_name(EXEC_OP_EXECVE)
    };
    if state.exec_attempts_by_tid.len() >= MAX_PENDING_EXEC_ATTEMPTS {
        let evicted = evict_oldest(&mut state.exec_attempts_by_tid, CACHE_EVICT_BATCH, |item| item.observed_at);
        warn!(evicted_entries = evicted, "Exec-Korrelationscache-Limit erreicht; älteste Einträge entfernt");
    }
    state.exec_attempts_by_tid.insert(
        event.tid,
        ExecAttemptContext {
            observed_at: Instant::now(),
            filename: filename.clone(),
            operation: if event.header.flags & FLAG_EXECVEAT != 0 {
                EXEC_OP_EXECVEAT
            } else {
                EXEC_OP_EXECVE
            },
        },
    );
    let parent = state
        .parent_by_child_tid
        .get(&event.tid)
        .filter(|parent| parent.observed_at.elapsed() <= PARENT_CONTEXT_TTL);

    let writable_path = filename.starts_with("/tmp/")
        || filename.starts_with("/var/tmp/")
        || filename.starts_with("/dev/shm/");
    let spawned_from_shell = parent
        .map(|parent| is_shell(&parent.parent_comm))
        .unwrap_or(false);

    if event.uid == 0 && writable_path && spawned_from_shell {
        if let Some(parent) = parent {
            warn!(
                event = "exec_attempt",
                operation,
                anomaly = "root_child_exec_from_writable_path",
                confidence = "medium",
                pid = event.pid,
                tid = event.tid,
                parent_tid = parent.parent_tid,
                parent_comm = %parent.parent_comm,
                uid = event.uid,
                comm,
                filename,
                argv,
                flags = event.header.flags,
                "Root-Prozess versucht Kind aus beschreibbarem Verzeichnis zu starten"
            );
        }
    } else if event.uid == 0 && writable_path {
        warn!(
            event = "exec_attempt",
            operation,
            anomaly = "root_exec_from_writable_path",
            confidence = "low",
            pid = event.pid,
            tid = event.tid,
            uid = event.uid,
            comm,
            filename,
            argv,
            flags = event.header.flags,
            "Root-Prozess versucht Executable aus beschreibbarem Verzeichnis zu starten"
        );
    } else {
        info!(
            event = "exec_attempt",
            operation,
            pid = event.pid,
            tid = event.tid,
            uid = event.uid,
            gid = event.gid,
            comm,
            filename,
            argv,
            argc = event.argc,
            flags = event.header.flags,
            "Prozess-Exec-Versuch erfasst"
        );
    }

    if event.header.flags & FLAG_PATH_READ_FAILED != 0
        || event.header.flags & FLAG_ARGS_READ_FAILED != 0
        || event.header.flags & FLAG_COMM_READ_FAILED != 0
    {
        debug!(pid = event.pid, flags = event.header.flags, "Exec-Telemetrie enthält Lesefehler");
    }
    if event.header.flags & FLAG_PATH_TRUNCATED != 0 || event.header.flags & FLAG_ARGS_TRUNCATED != 0 {
        debug!(pid = event.pid, flags = event.header.flags, "Exec-Daten wurden durch ABI-Limits gekürzt");
    }
}

fn report_process_fork(event: &ProcessForkEvent, state: &mut CorrelationState) {
    if event.child_tid == 0 || event.parent_tid == 0 {
        warn!("Ungültige Fork-IDs empfangen; Event ignoriert");
        return;
    }
    if state.parent_by_child_tid.len() >= MAX_TRACKED_TASKS {
        let evicted = evict_oldest(&mut state.parent_by_child_tid, CACHE_EVICT_BATCH, |item| item.observed_at);
        warn!(evicted_entries = evicted, "Parent-Child-Cache-Limit erreicht; älteste Einträge entfernt");
    }
    let parent_comm = c_array_to_string(&event.parent_comm);
    let child_comm = c_array_to_string(&event.child_comm);
    state.parent_by_child_tid.insert(
        event.child_tid,
        ParentContext {
            parent_tid: event.parent_tid,
            parent_comm: parent_comm.clone(),
            observed_at: Instant::now(),
        },
    );
    debug!(
        event = "process_fork",
        parent_tid = event.parent_tid,
        child_tid = event.child_tid,
        uid = event.uid,
        parent_comm,
        child_comm,
        "Task-Fork korreliert"
    );
}

fn report_process_exit(event: &ProcessExitEvent, state: &mut CorrelationState) {
    state.parent_by_child_tid.remove(&event.tid);
    state.parent_by_child_tid.retain(|_, parent| parent.parent_tid != event.tid);
    state.exec_attempts_by_tid.remove(&event.tid);
    state.directory_reads_by_tid.remove(&event.tid);
    state.module_attempts_by_tid.remove(&event.tid);
    debug!(pid = event.pid, tid = event.tid, comm = %c_array_to_string(&event.comm), "Task-Exit; Korrelationszustand bereinigt");
}

fn report_exec_result(event: &ExecAttemptResultEvent, state: &mut CorrelationState) {
    let attempt = state
        .exec_attempts_by_tid
        .remove(&event.tid)
        .filter(|item| item.observed_at.elapsed() <= EXEC_ATTEMPT_TTL);
    let operation = exec_operation_name(event.operation);
    if event.result < 0 {
        warn!(
            event = "exec_failure",
            outcome = "failed",
            operation,
            pid = event.pid,
            tid = event.tid,
            uid = event.uid,
            errno = event.result.saturating_neg(),
            result = event.result,
            filename = attempt.as_ref().map(|item| item.filename.as_str()).unwrap_or("<unpaired>"),
            comm = %c_array_to_string(&event.comm),
            paired_entry = attempt.is_some(),
            "Exec-Systemaufruf ist fehlgeschlagen"
        );
    } else {
        debug!(
            event = "exec_syscall_exit",
            operation,
            result = event.result,
            pid = event.pid,
            tid = event.tid,
            paired_entry = attempt.is_some(),
            "Exec-Systemaufruf hat einen nicht-negativen Rückgabewert geliefert"
        );
    }
}

fn report_process_exec(event: &ProcessExecEvent, state: &mut CorrelationState) {
    // During de-threading, exec by a non-leader thread can change its TID to
    // the thread-group ID. sched_process_exec.old_pid carries the former TID.
    let attempt = if event.old_pid != 0 {
        let by_old_pid = state.exec_attempts_by_tid.remove(&event.old_pid);
        by_old_pid.or_else(|| state.exec_attempts_by_tid.remove(&event.tid))
    } else {
        state.exec_attempts_by_tid.remove(&event.tid)
    };
    let paired = attempt
        .as_ref()
        .filter(|attempt| attempt.observed_at.elapsed() <= EXEC_ATTEMPT_TTL);
    let confirmed_filename = paired
        .map(|attempt| attempt.filename.as_str())
        .unwrap_or("<unpaired>");
    info!(
        event = "process_exec",
        outcome = "success",
        pid = event.pid,
        tid = event.tid,
        old_pid = event.old_pid,
        uid = event.uid,
        comm = %c_array_to_string(&event.comm),
        filename = confirmed_filename,
        exec_attempt_paired = paired.is_some(),
        exec_operation = paired.map(|attempt| exec_operation_name(attempt.operation)).unwrap_or("unknown"),
        flags = event.header.flags,
        "Erfolgreicher Prozess-Image-Wechsel bestätigt"
    );
}

fn report_module_load(event: &ModuleLoadEvent, state: &mut CorrelationState) {
    let paired_operation = state
        .module_attempts_by_tid
        .get(&event.tid)
        .filter(|attempt| attempt.observed_at.elapsed() <= MODULE_ATTEMPT_TTL)
        .map(|attempt| module_operation_name(attempt.operation))
        .unwrap_or("unpaired");
    warn!(
        event = "module_load",
        outcome = "loaded",
        pid = event.pid,
        tid = event.tid,
        uid = event.uid,
        taints = event.taints,
        paired_syscall = paired_operation,
        comm = %c_array_to_string(&event.comm),
        "Kernel-Modul-Ladeereignis vom Kernel-Tracepoint bestätigt"
    );
}

fn report_module_enter(event: &ModuleSyscallEvent, state: &mut CorrelationState) {
    if state.module_attempts_by_tid.len() >= MAX_PENDING_MODULE_ATTEMPTS {
        let evicted = evict_oldest(&mut state.module_attempts_by_tid, CACHE_EVICT_BATCH, |item| item.observed_at);
        warn!(evicted_entries = evicted, "Modul-Korrelationscache-Limit erreicht; älteste Einträge entfernt");
    }
    state.module_attempts_by_tid.insert(
        event.tid,
        ModuleAttemptContext {
            operation: event.operation,
            observed_at: Instant::now(),
        },
    );
    let operation = module_operation_name(event.operation);
    warn!(
        event = "module_syscall_attempt",
        operation,
        pid = event.pid,
        tid = event.tid,
        uid = event.uid,
        fd = event.fd,
        image_size = event.image_size,
        module_flags = event.module_flags,
        comm = %c_array_to_string(&event.comm),
        syscall_args_read_failed = event.header.flags & FLAG_SYSCALL_ARGS_READ_FAILED != 0,
        "Kernel-Modul-Ladeversuch beobachtet; Erfolg wird am Syscall-Exit festgestellt"
    );
}

fn report_module_exit(event: &ModuleSyscallResultEvent, state: &mut CorrelationState) {
    let expected = state.module_attempts_by_tid.remove(&event.tid);
    let operation = module_operation_name(event.operation);
    let paired_entry = expected
        .filter(|attempt| attempt.observed_at.elapsed() <= MODULE_ATTEMPT_TTL)
        .map(|attempt| attempt.operation == event.operation)
        .unwrap_or(false);
    if event.result == 0 {
        warn!(
            event = "module_syscall_result",
            outcome = "success",
            operation,
            pid = event.pid,
            tid = event.tid,
            uid = event.uid,
            paired_entry,
            comm = %c_array_to_string(&event.comm),
            "Kernel-Modul-Syscall war erfolgreich"
        );
    } else {
        info!(
            event = "module_syscall_result",
            outcome = "failed",
            operation,
            result = event.result,
            errno = event.result.saturating_neg(),
            pid = event.pid,
            tid = event.tid,
            paired_entry,
            "Kernel-Modul-Ladeversuch ist fehlgeschlagen"
        );
    }
}

fn report_getdents_enter(event: &DirectoryReadEnterEvent, state: &mut CorrelationState) {
    if state.directory_reads_by_tid.len() >= MAX_PENDING_DIR_READS {
        let evicted = evict_oldest(&mut state.directory_reads_by_tid, CACHE_EVICT_BATCH, |item| item.observed_at);
        warn!(evicted_entries = evicted, "getdents-Korrelationscache-Limit erreicht; älteste Einträge entfernt");
    }
    state.directory_reads_by_tid.insert(
        event.tid,
        DirectoryReadContext {
            dirfd: event.dirfd,
            requested_bytes: event.requested_bytes,
            enter_timestamp_ns: event.header.timestamp_ns,
            observed_at: Instant::now(),
        },
    );
}

fn report_getdents_exit(event: &DirectoryReadExitEvent, state: &mut CorrelationState) {
    let Some(start) = state.directory_reads_by_tid.remove(&event.tid) else {
        debug!(pid = event.pid, tid = event.tid, returned_bytes = event.returned_bytes, "getdents-Exit ohne passenden Entry");
        return;
    };
    if start.observed_at.elapsed() > DIRECTORY_READ_TTL {
        debug!(pid = event.pid, tid = event.tid, "getdents-Korrelation war abgelaufen");
        return;
    }
    if event.returned_bytes < 0 {
        debug!(pid = event.pid, tid = event.tid, result = event.returned_bytes, "getdents64 ist mit errno fehlgeschlagen");
        return;
    }
    let elapsed_ns = event.header.timestamp_ns.saturating_sub(start.enter_timestamp_ns);
    if event.returned_bytes > i64::from(start.requested_bytes) {
        warn!(
            event = "directory_enum_integrity",
            anomaly = "getdents_return_exceeds_requested_buffer",
            pid = event.pid,
            tid = event.tid,
            dirfd = start.dirfd,
            requested_bytes = start.requested_bytes,
            returned_bytes = event.returned_bytes,
            "Unplausible getdents64 Rückgabegröße"
        );
    } else {
        debug!(
            event = "directory_enum",
            pid = event.pid,
            tid = event.tid,
            uid = event.uid,
            dirfd = start.dirfd,
            requested_bytes = start.requested_bytes,
            returned_bytes = event.returned_bytes,
            elapsed_ns,
            "Verzeichnis-Enumeration beobachtet; keine Aussage über versteckte Einträge"
        );
    }
}

fn exec_operation_name(operation: u32) -> &'static str {
    match operation {
        EXEC_OP_EXECVE => "execve",
        EXEC_OP_EXECVEAT => "execveat",
        _ => "unknown",
    }
}

fn evict_oldest<V, F>(map: &mut HashMap<u32, V>, count: usize, observed_at: F) -> usize
where
    F: Fn(&V) -> Instant,
{
    let mut oldest: Vec<(u32, Instant)> = map
        .iter()
        .map(|(key, value)| (*key, observed_at(value)))
        .collect();
    oldest.sort_unstable_by_key(|(_, timestamp)| *timestamp);

    let mut removed = 0usize;
    for (key, _) in oldest.into_iter().take(count) {
        if map.remove(&key).is_some() {
            removed += 1;
        }
    }
    removed
}

fn prune_stale_correlations(state: &mut CorrelationState) {
    let now = Instant::now();
    let before = state.parent_by_child_tid.len()
        + state.exec_attempts_by_tid.len()
        + state.directory_reads_by_tid.len()
        + state.module_attempts_by_tid.len();

    state.parent_by_child_tid.retain(|_, value| now.duration_since(value.observed_at) <= PARENT_CONTEXT_TTL);
    state.exec_attempts_by_tid.retain(|_, value| now.duration_since(value.observed_at) <= EXEC_ATTEMPT_TTL);
    state.directory_reads_by_tid.retain(|_, value| now.duration_since(value.observed_at) <= DIRECTORY_READ_TTL);
    state.module_attempts_by_tid.retain(|_, value| now.duration_since(value.observed_at) <= MODULE_ATTEMPT_TTL);

    let after = state.parent_by_child_tid.len()
        + state.exec_attempts_by_tid.len()
        + state.directory_reads_by_tid.len()
        + state.module_attempts_by_tid.len();
    let expired = before.saturating_sub(after);
    if expired > 0 {
        debug!(expired_correlations = expired, "Abgelaufene Korrelationszustände entfernt");
    }
}

fn module_operation_name(operation: u32) -> &'static str {
    match operation {
        MODULE_OP_INIT_MODULE => "init_module",
        MODULE_OP_FINIT_MODULE => "finit_module",
        _ => "unknown",
    }
}

fn is_shell(comm: &str) -> bool {
    matches!(comm, "sh" | "bash" | "dash" | "zsh" | "fish" | "ksh")
        || comm.starts_with("python")
        || matches!(comm, "perl" | "ruby" | "node")
}

fn format_argv(event: &ExecEvent) -> String {
    let mut values = Vec::with_capacity(usize::from(event.argc));
    let mut redact_next = false;
    for slot in 0..EXEC_ARG_SLOTS.min(usize::from(event.argc)) {
        let start = slot * EXEC_ARG_SLOT_LEN;
        let end = start + EXEC_ARG_SLOT_LEN;
        let value = c_array_to_string(&event.argv[start..end]);
        let lower = value.to_ascii_lowercase();
        let sensitive_option = ["--password", "--token", "--secret", "--api-key", "--apikey"]
            .iter()
            .any(|key| lower == *key || lower.starts_with(&format!("{key}=")));

        if redact_next {
            values.push("[REDACTED]".to_owned());
            redact_next = false;
        } else if ["password=", "token=", "secret=", "api_key=", "apikey="]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            let key = value.split('=').next().unwrap_or("arg");
            values.push(format!("{key}=[REDACTED]"));
        } else {
            values.push(value);
            redact_next = sensitive_option && !lower.contains('=');
        }
    }
    values.join(" ")
}

fn c_array_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tracepoint_array_field_names() {
        let format = "field:char comm[16]; offset:8; size:16; signed:0;\nfield:int pid; offset:24; size:4; signed:1;\n";
        assert_eq!(tracepoint_field_layout(format, "comm").expect("comm layout"), (8, 16));
        assert_eq!(tracepoint_field_layout(format, "pid").expect("pid layout"), (24, 4));
    }

    #[test]
    fn rejects_unknown_tracepoint_fields() {
        assert!(tracepoint_field_layout("field:int pid; offset:24; size:4;", "child_pid").is_err());
    }

    #[test]
    fn argv_redacts_sensitive_options_and_inline_values() {
        let mut event = <ExecEvent as bytemuck::Zeroable>::zeroed();
        event.argc = 3;
        let args = ["--token", "sensitive-value", "--password=secret"];
        for (index, value) in args.iter().enumerate() {
            let start = index * EXEC_ARG_SLOT_LEN;
            let bytes = value.as_bytes();
            event.argv[start..start + bytes.len()].copy_from_slice(bytes);
        }
        assert_eq!(format_argv(&event), "--token [REDACTED] --password=[REDACTED]");
    }

    #[test]
    fn shell_heuristic_is_explicit() {
        assert!(is_shell("bash"));
        assert!(is_shell("python3"));
        assert!(!is_shell("systemd"));
    }

    #[test]
    fn exec_operation_names_are_stable() {
        assert_eq!(exec_operation_name(EXEC_OP_EXECVE), "execve");
        assert_eq!(exec_operation_name(EXEC_OP_EXECVEAT), "execveat");
        assert_eq!(exec_operation_name(u32::MAX), "unknown");
    }

    #[test]
    fn stale_correlation_entries_are_expired() {
        let mut state = CorrelationState::default();
        state.parent_by_child_tid.insert(
            22,
            ParentContext {
                parent_tid: 11,
                parent_comm: "bash".to_owned(),
                observed_at: Instant::now() - PARENT_CONTEXT_TTL - Duration::from_secs(1),
            },
        );
        state.exec_attempts_by_tid.insert(
            22,
            ExecAttemptContext {
                observed_at: Instant::now() - EXEC_ATTEMPT_TTL - Duration::from_secs(1),
                filename: "/tmp/payload".to_owned(),
                operation: EXEC_OP_EXECVE,
            },
        );
        prune_stale_correlations(&mut state);
        assert!(state.parent_by_child_tid.is_empty());
        assert!(state.exec_attempts_by_tid.is_empty());
    }

    #[test]
    fn cache_pressure_evicts_oldest_entries_only() {
        let now = Instant::now();
        let mut cache = HashMap::new();
        cache.insert(1u32, now - Duration::from_secs(3));
        cache.insert(2u32, now - Duration::from_secs(2));
        cache.insert(3u32, now - Duration::from_secs(1));

        let removed = evict_oldest(&mut cache, 1, |timestamp| *timestamp);

        assert_eq!(removed, 1);
        assert!(!cache.contains_key(&1));
        assert!(cache.contains_key(&2));
        assert!(cache.contains_key(&3));
    }

    #[test]
    fn successful_exec_correlates_using_old_tid_after_dethreading() {
        let mut state = CorrelationState::default();
        state.exec_attempts_by_tid.insert(
            101,
            ExecAttemptContext {
                observed_at: Instant::now(),
                filename: "/usr/bin/id".to_owned(),
                operation: EXEC_OP_EXECVE,
            },
        );
        let event = ProcessExecEvent {
            header: EventHeader {
                abi_version: ABI_VERSION,
                event_type: EVENT_PROCESS_EXEC,
                flags: 0,
                timestamp_ns: 1,
            },
            pid: 100,
            tid: 100,
            uid: 0,
            old_pid: 101,
            comm: [0; 16],
        };
        report_process_exec(&event, &mut state);
        assert!(!state.exec_attempts_by_tid.contains_key(&101));
    }
}
