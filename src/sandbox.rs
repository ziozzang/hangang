//! Linux Lua workers use a syscall allowlist after executable initialization.
//! This complements VM quotas and process replacement; the gateway itself is
//! never filtered. Unsupported architectures reject worker startup.
use anyhow::{Context, Result, ensure};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub fn install() -> Result<()> {
    use libc::{sock_filter, sock_fprog};
    fn statement(code: u16, k: u32) -> sock_filter {
        sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(k: u32, jt: u8, jf: u8) -> sock_filter {
        sock_filter {
            code: 0x15,
            jt,
            jf,
            k,
        }
    }
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    const KILL: u32 = 0x80000000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let mut code = vec![
        statement(0x20, 4),
        jump(ARCH, 1, 0),
        statement(0x06, KILL),
        statement(0x20, 0),
    ];
    // mmap/mprotect may allocate data pages, but cannot create executable code.
    for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
        code.extend([
            jump(syscall as u32, 0, 4),
            statement(0x20, 32),
            statement(0x54, libc::PROT_EXEC as u32),
            jump(0, 0, 1),
            statement(0x06, ALLOW),
            statement(0x06, DENY),
        ]);
        // The nonmatching branch must reload the syscall after skipping this rule.
        let at = code.len() - 6;
        code[at].jf = 5;
        code.push(statement(0x20, 0));
    }
    // IPC remains restricted to inherited stdin/stdout/stderr. No filesystem,
    // networking, new processes, credential changes or tracing are permitted.
    for syscall in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
    ] {
        code.extend([
            jump(syscall as u32, 0, 4),
            statement(0x20, 16),
            sock_filter {
                code: 0x25,
                jt: 1,
                jf: 0,
                k: 2,
            },
            statement(0x06, ALLOW),
            statement(0x06, DENY),
        ]);
    }
    let allowed = [
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_gettimeofday,
        libc::SYS_getrandom,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_sched_yield,
        libc::SYS_restart_syscall,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    for syscall in allowed {
        code.extend([jump(syscall as u32, 0, 1), statement(0x06, ALLOW)]);
    }
    code.push(statement(0x06, DENY));
    let program = sock_fprog {
        len: code.len().try_into()?,
        filter: code.as_mut_ptr(),
    };
    // SAFETY: the caller is the dedicated single-threaded worker; BPF memory
    // remains valid until prctl copies it into the kernel.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0,
        "no_new_privs failed"
    );
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program as *const sock_fprog) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("install Lua worker seccomp allowlist");
    }
    Ok(())
}
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn install() -> Result<()> {
    anyhow::bail!("Lua syscall isolation requires Linux x86_64 or aarch64")
}

/// Runs only in a dedicated child process launched by integration tests.
#[cfg(target_os = "linux")]
pub fn self_check() -> Result<()> {
    install()?;
    let file = std::fs::File::open("/dev/null");
    ensure!(
        file.is_err_and(|e| e.raw_os_error() == Some(libc::EPERM)),
        "filesystem access was not denied"
    );
    // SAFETY: no pointers; a mistakenly allowed socket is closed immediately.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        anyhow::bail!("socket creation was not denied");
    }
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "unexpected socket error"
    );
    // SAFETY: requests a fresh private page; on unexpected success it is unmapped.
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if memory != libc::MAP_FAILED {
        unsafe { libc::munmap(memory, 4096) };
        anyhow::bail!("executable mapping was not denied");
    }
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "unexpected mmap error"
    );
    println!("worker syscall restrictions verified");
    Ok(())
}
