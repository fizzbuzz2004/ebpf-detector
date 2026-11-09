#![no_std]

//! Stable wire ABI shared by the BPF and userspace components.
//!
//! ABI rules:
//! - fixed-width integer fields only; no pointers, `usize`, `bool`, `String`, or references;
//! - every event starts with the same 16-byte `EventHeader`;
//! - every event type has an exact, compile-time size checked below;
//! - changing a field or event layout requires incrementing `ABI_VERSION`.

use bytemuck::{Pod, Zeroable};

pub const ABI_VERSION: u16 = 2;

pub const EVENT_EXEC_ATTEMPT: u16 = 1;
pub const EVENT_MODULE_SYSCALL_ENTER: u16 = 2;
pub const EVENT_MODULE_SYSCALL_EXIT: u16 = 3;
pub const EVENT_GETDENTS_ENTER: u16 = 4;
pub const EVENT_GETDENTS_EXIT: u16 = 5;
pub const EVENT_PROCESS_FORK: u16 = 6;
pub const EVENT_PROCESS_EXIT: u16 = 7;
pub const EVENT_PROCESS_EXEC: u16 = 8;
pub const EVENT_MODULE_LOAD: u16 = 9;
pub const EVENT_EXEC_RESULT: u16 = 10;

pub const EXEC_OP_EXECVE: u32 = 1;
pub const EXEC_OP_EXECVEAT: u32 = 2;

pub const MODULE_OP_INIT_MODULE: u32 = 1;
pub const MODULE_OP_FINIT_MODULE: u32 = 2;

pub const TASK_COMM_LEN: usize = 16;
pub const EXEC_PATH_LEN: usize = 192;
pub const EXEC_ARG_SLOTS: usize = 4;
pub const EXEC_ARG_SLOT_LEN: usize = 32;
pub const EXEC_ARG_BYTES: usize = EXEC_ARG_SLOTS * EXEC_ARG_SLOT_LEN;

pub const FLAG_PATH_READ_FAILED: u32 = 1 << 0;
pub const FLAG_ARGS_READ_FAILED: u32 = 1 << 1;
pub const FLAG_PATH_TRUNCATED: u32 = 1 << 2;
pub const FLAG_ARGS_TRUNCATED: u32 = 1 << 3;
pub const FLAG_COMM_READ_FAILED: u32 = 1 << 4;
pub const FLAG_SYSCALL_ARGS_READ_FAILED: u32 = 1 << 5;
pub const FLAG_TRACEPOINT_READ_FAILED: u32 = 1 << 6;
pub const FLAG_EXECVEAT: u32 = 1 << 7;

/// Common 16-byte prefix for all ring-buffer records.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct EventHeader {
    pub abi_version: u16,
    pub event_type: u16,
    pub flags: u32,
    pub timestamp_ns: u64,
}

/// One `execve(2)` or `execveat(2)` attempt. `argv` contains four fixed,
/// NUL-terminated slots. `FLAG_EXECVEAT` distinguishes execveat events.
/// Successful image changes are confirmed by `sched_process_exec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; EXEC_PATH_LEN],
    pub argv: [u8; EXEC_ARG_BYTES],
    pub argc: u8,
    pub reserved: [u8; 7],
}

/// Return status for a failed `execve(2)` / `execveat(2)` syscall. Successful
/// image replacement is normally observed through `sched_process_exec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ExecAttemptResultEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub operation: u32,
    pub result: i64,
    pub comm: [u8; TASK_COMM_LEN],
}

/// `init_module(2)` / `finit_module(2)` entry telemetry. It deliberately does
/// not expose user pointers or kernel addresses. A matching exit event reports
/// whether the syscall returned success.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ModuleSyscallEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub operation: u32,
    pub fd: i32,
    pub module_flags: u32,
    pub image_size: u64,
    pub comm: [u8; TASK_COMM_LEN],
}

/// Syscall exit status for a module insertion attempt. `result == 0` means the
/// syscall returned success; negative values are kernel errno values.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ModuleSyscallResultEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub operation: u32,
    pub result: i64,
    pub comm: [u8; TASK_COMM_LEN],
}

/// Entry metadata for `getdents64`. No dirent contents are copied.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct DirectoryReadEnterEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub dirfd: i32,
    pub requested_bytes: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub reserved: u32,
}

/// Exit metadata for `getdents64`. Userspace correlates this with the entry by
/// TID. The record is telemetry only and is not proof of a hidden file.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct DirectoryReadExitEvent {
    pub header: EventHeader,
    pub returned_bytes: i64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub reserved: u32,
}

/// Task-level fork relationship. `parent_tid` and `child_tid` intentionally
/// follow sched tracepoint task IDs (not necessarily thread-group IDs).
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcessForkEvent {
    pub header: EventHeader,
    pub parent_tid: u32,
    pub child_tid: u32,
    pub uid: u32,
    pub parent_comm: [u8; TASK_COMM_LEN],
    pub child_comm: [u8; TASK_COMM_LEN],
    pub reserved: u32,
}

/// Task exit signal used to expire userspace correlation state.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub reserved: u32,
}

/// Successful image replacement emitted by `sched_process_exec`.
/// This is the authoritative success signal paired with `execve` or `execveat`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcessExecEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub old_pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

/// Kernel module became live, observed through `module:module_load`.
/// The event contains taint metadata and no kernel pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ModuleLoadEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub taints: u32,
    pub comm: [u8; TASK_COMM_LEN],
}

// These compile-time assertions protect the cross-boundary ABI and keep all
// ring-buffer records 8-byte aligned without implicit padding.
const _: () = assert!(core::mem::size_of::<EventHeader>() == 16);
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 376);
const _: () = assert!(core::mem::size_of::<ExecAttemptResultEvent>() == 56);
const _: () = assert!(core::mem::size_of::<ModuleSyscallEvent>() == 64);
const _: () = assert!(core::mem::size_of::<ModuleSyscallResultEvent>() == 56);
const _: () = assert!(core::mem::size_of::<DirectoryReadEnterEvent>() == 56);
const _: () = assert!(core::mem::size_of::<DirectoryReadExitEvent>() == 56);
const _: () = assert!(core::mem::size_of::<ProcessForkEvent>() == 64);
const _: () = assert!(core::mem::size_of::<ProcessExitEvent>() == 48);
const _: () = assert!(core::mem::size_of::<ProcessExecEvent>() == 48);
const _: () = assert!(core::mem::size_of::<ModuleLoadEvent>() == 48);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_events_start_with_the_common_header() {
        let event = ExecEvent::zeroed();
        let bytes = bytemuck::bytes_of(&event);
        let header = bytemuck::pod_read_unaligned::<EventHeader>(&bytes[..16]);
        assert_eq!(header.abi_version, ABI_VERSION);
    }

    #[test]
    fn event_layouts_are_aligned_for_ring_buffer_records() {
        for size in [
            core::mem::size_of::<ExecEvent>(),
            core::mem::size_of::<ExecAttemptResultEvent>(),
            core::mem::size_of::<ModuleSyscallEvent>(),
            core::mem::size_of::<ModuleSyscallResultEvent>(),
            core::mem::size_of::<DirectoryReadEnterEvent>(),
            core::mem::size_of::<DirectoryReadExitEvent>(),
            core::mem::size_of::<ProcessForkEvent>(),
            core::mem::size_of::<ProcessExitEvent>(),
            core::mem::size_of::<ProcessExecEvent>(),
            core::mem::size_of::<ModuleLoadEvent>(),
        ] {
            assert_eq!(size % 8, 0);
        }
    }
}
