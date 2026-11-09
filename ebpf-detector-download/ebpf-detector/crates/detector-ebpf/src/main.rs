#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
        bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use bytemuck::Zeroable;
use detector_common::{
    ABI_VERSION, DirectoryReadEnterEvent, DirectoryReadExitEvent, EVENT_EXEC_ATTEMPT,
    EVENT_EXEC_RESULT,
    EVENT_GETDENTS_ENTER, EVENT_GETDENTS_EXIT, EVENT_MODULE_SYSCALL_ENTER,
    EVENT_MODULE_SYSCALL_EXIT, EVENT_MODULE_LOAD, EVENT_PROCESS_EXEC, EVENT_PROCESS_EXIT,
    EVENT_PROCESS_FORK, EXEC_ARG_SLOT_LEN, EXEC_ARG_SLOTS, EventHeader, ExecAttemptResultEvent,
    ExecEvent, EXEC_OP_EXECVE, EXEC_OP_EXECVEAT, FLAG_EXECVEAT,
    FLAG_ARGS_READ_FAILED, FLAG_ARGS_TRUNCATED,
    FLAG_COMM_READ_FAILED, FLAG_PATH_READ_FAILED, FLAG_PATH_TRUNCATED,
    FLAG_SYSCALL_ARGS_READ_FAILED,
    FLAG_TRACEPOINT_READ_FAILED, ModuleSyscallEvent,
    ModuleLoadEvent, ModuleSyscallResultEvent, MODULE_OP_FINIT_MODULE, MODULE_OP_INIT_MODULE,
    ProcessExecEvent, ProcessExitEvent, ProcessForkEvent, TASK_COMM_LEN,
};

// Ubuntu 24.04 x86_64 / kernel 6.8 syscall tracepoint layouts. The daemon
// validates these against tracefs before attaching any program.
const EXECVE_FILENAME_OFFSET: usize = 16;
const EXECVE_ARGV_OFFSET: usize = 24;
const RAW_SYSCALL_ARGS_OFFSET: usize = 16;
const SYSCALL_EXIT_RET_OFFSET: usize = 16;

// Linux v6.8 sched tracepoint layouts. Fail closed on an unknown layout.
const SCHED_FORK_PARENT_COMM_OFFSET: usize = 8;
const SCHED_FORK_PARENT_TID_OFFSET: usize = 24;
const SCHED_FORK_CHILD_COMM_OFFSET: usize = 28;
const SCHED_FORK_CHILD_TID_OFFSET: usize = 44;
const SCHED_EXIT_COMM_OFFSET: usize = 8;
const SCHED_EXIT_PID_OFFSET: usize = 24;
const SCHED_EXEC_OLD_PID_OFFSET: usize = 16;
const MODULE_LOAD_TAINTS_OFFSET: usize = 8;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

/// Per-CPU counter incremented when an event cannot reserve ring-buffer space.
/// Userspace reads and aggregates all CPU values periodically.
#[map]
static LOST_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU count of probe-context read failures or malformed tracepoint records.
#[map]
static PROBE_ERRORS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn make_header(event_type: u16) -> EventHeader {
    EventHeader {
        abi_version: ABI_VERSION,
        event_type,
        flags: 0,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
    }
}

#[inline(always)]
fn identity() -> (u32, u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    ((pid_tgid >> 32) as u32, pid_tgid as u32, uid_gid as u32)
}

#[inline(always)]
fn increment_counter(counter: Option<*mut u64>) {
    if let Some(counter) = counter {
        // SAFETY: PerCpuArray::get_ptr_mut returns the current CPU's value.
        // BPF programs execute with migration/preemption disabled; this value
        // is therefore updated only by the current CPU while this program runs.
        unsafe {
            *counter = (*counter).wrapping_add(1);
        }
    }
}

#[inline(always)]
fn increment_lost_events() {
    increment_counter(LOST_EVENTS.get_ptr_mut(0));
}

#[inline(always)]
fn increment_probe_errors() {
    increment_counter(PROBE_ERRORS.get_ptr_mut(0));
}

#[tracepoint]
pub fn execve_enter(ctx: TracePointContext) -> u32 {
    if try_execve_enter(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_execve_enter(ctx: TracePointContext) -> Result<(), i32> {
    // SAFETY: The daemon validates both pointer fields against the active
    // sys_enter_execve tracepoint format before attaching this program.
    let filename_ptr = unsafe { ctx.read_at::<*const u8>(EXECVE_FILENAME_OFFSET)? };
    // SAFETY: Same validated tracepoint context and layout as above.
    let argv_ptr = unsafe { ctx.read_at::<*const *const u8>(EXECVE_ARGV_OFFSET)? };
    emit_exec_attempt(filename_ptr, argv_ptr, 0)
}

#[tracepoint]
pub fn execveat_enter(ctx: TracePointContext) -> u32 {
    if try_execveat_enter(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_execveat_enter(ctx: TracePointContext) -> Result<(), i32> {
    // SAFETY: sys_enter_execveat uses the generic syscall args[6] layout;
    // userspace validates args at offset 16 and size 48 before attach.
    let args = unsafe { ctx.read_at::<[u64; 6]>(RAW_SYSCALL_ARGS_OFFSET)? };
    // execveat(dirfd, filename, argv, envp, flags): args[1] and args[2].
    emit_exec_attempt(args[1] as *const u8, args[2] as *const *const u8, FLAG_EXECVEAT)
}

fn emit_exec_attempt(
    filename_ptr: *const u8,
    argv_ptr: *const *const u8,
    extra_flags: u32,
) -> Result<(), i32> {
    let Some(mut record) = EVENTS.reserve::<ExecEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ExecEvent::zeroed());

    event.header = make_header(EVENT_EXEC_ATTEMPT);
    event.header.flags |= extra_flags;
    let (pid, tid, uid) = identity();
    let uid_gid = bpf_get_current_uid_gid();
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    event.gid = (uid_gid >> 32) as u32;

    match bpf_get_current_comm() {
        Ok(comm) => event.comm = comm.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }

    // SAFETY: BPF helper performs a fault-safe, bounded read from userspace.
    match unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut event.filename[..]) } {
        Ok(path) => {
            if path.len() >= event.filename.len().saturating_sub(1) {
                event.header.flags |= FLAG_PATH_TRUNCATED;
            }
        }
        Err(_) => event.header.flags |= FLAG_PATH_READ_FAILED,
    }

    if argv_ptr.is_null() {
        event.header.flags |= FLAG_ARGS_READ_FAILED;
    } else {
        let mut slot = 0usize;
        while slot < EXEC_ARG_SLOTS {
            let slot_ptr = argv_ptr.wrapping_add(slot);
            // SAFETY: BPF helper validates the userspace read and copies only a pointer-sized value.
            let arg_ptr = match unsafe { bpf_probe_read_user::<*const u8>(slot_ptr) } {
                Ok(ptr) => ptr,
                Err(_) => {
                    event.header.flags |= FLAG_ARGS_READ_FAILED;
                    break;
                }
            };
            if arg_ptr.is_null() {
                break;
            }

            let start = slot * EXEC_ARG_SLOT_LEN;
            let end = start + EXEC_ARG_SLOT_LEN;
            // SAFETY: Destination is a fixed slot inside the ABI-sized argv array.
            match unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut event.argv[start..end]) } {
                Ok(arg) => {
                    if arg.len() >= EXEC_ARG_SLOT_LEN.saturating_sub(1) {
                        event.header.flags |= FLAG_ARGS_TRUNCATED;
                    }
                    event.argc = event.argc.saturating_add(1);
                }
                Err(_) => {
                    event.header.flags |= FLAG_ARGS_READ_FAILED;
                    break;
                }
            }
            slot += 1;
        }
        if slot == EXEC_ARG_SLOTS {
            // SAFETY: Read one additional argv pointer only to distinguish an
            // exact four-argument vector from an actually truncated vector.
            let next_arg = unsafe {
                bpf_probe_read_user::<*const u8>(argv_ptr.wrapping_add(EXEC_ARG_SLOTS))
            };
            match next_arg {
                Ok(pointer) if !pointer.is_null() => {
                    event.header.flags |= FLAG_ARGS_TRUNCATED;
                }
                Ok(_) => {}
                Err(_) => event.header.flags |= FLAG_ARGS_READ_FAILED,
            }
        }
    }

    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn execve_exit(ctx: TracePointContext) -> u32 {
    if try_exec_result(ctx, EXEC_OP_EXECVE).is_err() {
        increment_probe_errors();
    }
    0
}

#[tracepoint]
pub fn execveat_exit(ctx: TracePointContext) -> u32 {
    if try_exec_result(ctx, EXEC_OP_EXECVEAT).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_exec_result(ctx: TracePointContext, operation: u32) -> Result<(), i32> {
    // Read before reserving: an invalid context must not leave an uncommitted
    // reservation in the shared ring buffer.
    // SAFETY: The daemon validates `ret` at offset 16 in both syscall-exit formats.
    let result = unsafe { ctx.read_at::<i64>(SYSCALL_EXIT_RET_OFFSET)? };
    let comm = bpf_get_current_comm();
    let comm_failed = comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ExecAttemptResultEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ExecAttemptResultEvent::zeroed());
    event.header = make_header(EVENT_EXEC_RESULT);
    event.operation = operation;
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    event.result = result;
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    if comm_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn process_fork(ctx: TracePointContext) -> u32 {
    if try_process_fork(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_process_fork(ctx: TracePointContext) -> Result<(), i32> {
    // Read and validate all tracepoint fields before reserving ring-buffer
    // space. A read failure must never leave an uncommitted record blocking
    // later consumers.
    // SAFETY: The daemon validates every offset using the live sched tracepoint format.
    let parent_comm = unsafe { ctx.read_at::<[u8; TASK_COMM_LEN]>(SCHED_FORK_PARENT_COMM_OFFSET)? };
    // SAFETY: Same validated tracepoint format as above.
    let parent_tid = unsafe { ctx.read_at::<i32>(SCHED_FORK_PARENT_TID_OFFSET)? as u32 };
    // SAFETY: Same validated tracepoint format as above.
    let child_comm = unsafe { ctx.read_at::<[u8; TASK_COMM_LEN]>(SCHED_FORK_CHILD_COMM_OFFSET)? };
    // SAFETY: Same validated tracepoint format as above.
    let child_tid = unsafe { ctx.read_at::<i32>(SCHED_FORK_CHILD_TID_OFFSET)? as u32 };

    let Some(mut record) = EVENTS.reserve::<ProcessForkEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ProcessForkEvent::zeroed());
    event.header = make_header(EVENT_PROCESS_FORK);
    let (_, _, uid) = identity();
    event.uid = uid;
    event.parent_comm = parent_comm.into();
    event.parent_tid = parent_tid;
    event.child_comm = child_comm.into();
    event.child_tid = child_tid;

    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn process_exit(ctx: TracePointContext) -> u32 {
    if try_process_exit(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_process_exit(ctx: TracePointContext) -> Result<(), i32> {
    // Read all tracepoint data before reserving ring-buffer space.
    // SAFETY: Both offsets are checked against sched_process_exit/format by userspace.
    let comm = unsafe { ctx.read_at::<[u8; TASK_COMM_LEN]>(SCHED_EXIT_COMM_OFFSET) };
    // SAFETY: Same validated tracepoint record; the field is task->pid.
    let task_pid = unsafe { ctx.read_at::<i32>(SCHED_EXIT_PID_OFFSET) };
    let read_failed = comm.is_err() || task_pid.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ProcessExitEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ProcessExitEvent::zeroed());
    event.header = make_header(EVENT_PROCESS_EXIT);
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_TRACEPOINT_READ_FAILED,
    }
    match task_pid {
        Ok(value) => event.tid = value as u32,
        Err(_) => event.header.flags |= FLAG_TRACEPOINT_READ_FAILED,
    }
    if read_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn process_exec(ctx: TracePointContext) -> u32 {
    if try_process_exec(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_process_exec(ctx: TracePointContext) -> Result<(), i32> {
    // SAFETY: The daemon verifies old_pid at offset 16 in the live tracepoint format.
    let old_pid = unsafe { ctx.read_at::<i32>(SCHED_EXEC_OLD_PID_OFFSET) };
    let comm = bpf_get_current_comm();
    let read_failed = old_pid.is_err() || comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ProcessExecEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ProcessExecEvent::zeroed());
    event.header = make_header(EVENT_PROCESS_EXEC);
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    match old_pid {
        Ok(value) => event.old_pid = value as u32,
        Err(_) => event.header.flags |= FLAG_TRACEPOINT_READ_FAILED,
    }
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    if read_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn module_load(ctx: TracePointContext) -> u32 {
    if try_module_load(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_module_load(ctx: TracePointContext) -> Result<(), i32> {
    // SAFETY: The daemon validates `taints` at offset 8 in module:module_load.
    let taints = unsafe { ctx.read_at::<u32>(MODULE_LOAD_TAINTS_OFFSET) };
    let comm = bpf_get_current_comm();
    let read_failed = taints.is_err() || comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ModuleLoadEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ModuleLoadEvent::zeroed());
    event.header = make_header(EVENT_MODULE_LOAD);
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    match taints {
        Ok(value) => event.taints = value,
        Err(_) => event.header.flags |= FLAG_TRACEPOINT_READ_FAILED,
    }
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    if read_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn init_module_enter(ctx: TracePointContext) -> u32 {
    if try_module_syscall_enter(ctx, MODULE_OP_INIT_MODULE).is_err() {
        increment_probe_errors();
    }
    0
}

#[tracepoint]
pub fn finit_module_enter(ctx: TracePointContext) -> u32 {
    if try_module_syscall_enter(ctx, MODULE_OP_FINIT_MODULE).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_module_syscall_enter(ctx: TracePointContext, operation: u32) -> Result<(), i32> {
    // SAFETY: All syscall tracepoints expose generic args[6] at validated offset 16.
    // Values are copied as fixed-width u64s; user pointers are never dereferenced.
    let args = unsafe { ctx.read_at::<[u64; 6]>(RAW_SYSCALL_ARGS_OFFSET) };
    let comm = bpf_get_current_comm();
    let read_failed = args.is_err() || comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ModuleSyscallEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ModuleSyscallEvent::zeroed());
    event.header = make_header(EVENT_MODULE_SYSCALL_ENTER);
    event.operation = operation;
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    match args {
        Ok(values) => match operation {
            MODULE_OP_INIT_MODULE => {
                event.fd = -1;
                event.image_size = values[1];
            }
            MODULE_OP_FINIT_MODULE => {
                event.fd = values[0] as i32;
                event.module_flags = values[2] as u32;
            }
            _ => event.header.flags |= FLAG_SYSCALL_ARGS_READ_FAILED,
        },
        Err(_) => event.header.flags |= FLAG_SYSCALL_ARGS_READ_FAILED,
    }
    if read_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn init_module_exit(ctx: TracePointContext) -> u32 {
    if try_module_syscall_exit(ctx, MODULE_OP_INIT_MODULE).is_err() {
        increment_probe_errors();
    }
    0
}

#[tracepoint]
pub fn finit_module_exit(ctx: TracePointContext) -> u32 {
    if try_module_syscall_exit(ctx, MODULE_OP_FINIT_MODULE).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_module_syscall_exit(ctx: TracePointContext, operation: u32) -> Result<(), i32> {
    // Read before reserving to ensure a context error cannot strand a ring slot.
    // SAFETY: The daemon validates `ret` offset in this syscall-exit tracepoint.
    let result = unsafe { ctx.read_at::<i64>(SYSCALL_EXIT_RET_OFFSET)? };
    let comm = bpf_get_current_comm();
    let comm_failed = comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<ModuleSyscallResultEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(ModuleSyscallResultEvent::zeroed());
    event.header = make_header(EVENT_MODULE_SYSCALL_EXIT);
    event.operation = operation;
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    event.result = result;
    if let Ok(value) = comm {
        event.comm = value.into();
    } else {
        event.header.flags |= FLAG_COMM_READ_FAILED;
    }
    if comm_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn getdents_enter(ctx: TracePointContext) -> u32 {
    if try_getdents_enter(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_getdents_enter(ctx: TracePointContext) -> Result<(), i32> {
    // SAFETY: Generic syscall args[6] offset is validated before attaching.
    let args = unsafe { ctx.read_at::<[u64; 6]>(RAW_SYSCALL_ARGS_OFFSET) };
    let comm = bpf_get_current_comm();
    let read_failed = args.is_err() || comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<DirectoryReadEnterEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(DirectoryReadEnterEvent::zeroed());
    event.header = make_header(EVENT_GETDENTS_ENTER);
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    match args {
        Ok(values) => {
            event.dirfd = values[0] as i32;
            event.requested_bytes = values[2].min(u32::MAX as u64) as u32;
        }
        Err(_) => event.header.flags |= FLAG_SYSCALL_ARGS_READ_FAILED,
    }
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    if read_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[tracepoint]
pub fn getdents_exit(ctx: TracePointContext) -> u32 {
    if try_getdents_exit(ctx).is_err() {
        increment_probe_errors();
    }
    0
}

fn try_getdents_exit(ctx: TracePointContext) -> Result<(), i32> {
    // Read before reserving to ensure a context error cannot strand a ring slot.
    // SAFETY: The daemon validates return-value offset 16 against tracefs.
    let returned_bytes = unsafe { ctx.read_at::<i64>(SYSCALL_EXIT_RET_OFFSET)? };
    let comm = bpf_get_current_comm();
    let comm_failed = comm.is_err();
    let (pid, tid, uid) = identity();
    let Some(mut record) = EVENTS.reserve::<DirectoryReadExitEvent>(0) else {
        increment_lost_events();
        return Ok(());
    };
    let event = record.write(DirectoryReadExitEvent::zeroed());
    event.header = make_header(EVENT_GETDENTS_EXIT);
    event.pid = pid;
    event.tid = tid;
    event.uid = uid;
    event.returned_bytes = returned_bytes;
    match comm {
        Ok(value) => event.comm = value.into(),
        Err(_) => event.header.flags |= FLAG_COMM_READ_FAILED,
    }
    if comm_failed {
        increment_probe_errors();
    }
    record.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
