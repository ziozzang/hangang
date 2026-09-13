//! Unix supervisor/worker control and listening-file-descriptor handoff.
//!
//! Each descriptor travels in its own `SCM_RIGHTS` message over a private
//! `SOCK_SEQPACKET` socket. This avoids ancillary-data batch limits and keeps
//! message boundaries unambiguous.

#![cfg(unix)]

use std::{
    collections::HashSet,
    io,
    mem::{size_of, zeroed},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    ptr,
    time::{Duration, Instant},
};

const MAGIC: &[u8; 8] = b"HNGFD001";
const FRAME_LEN: usize = 40;
pub const MAX_HANDOFF_DESCRIPTORS: usize = 2048;

const ACME_HTTP_FD: u8 = 6;
const PUBLIC_FD: u8 = 1;
const ADMIN_FD: u8 = 2;
const CONFIG_LOCK_FD: u8 = 3;
const TCP_FD: u8 = 4;
const CONFIG_SNAPSHOT_FD: u8 = 5;
const DOCKER_LOCK_FD: u8 = 7;
const WORKLOAD_HTTP_FD: u8 = 8;
const FREEZE_EXPORT: u8 = 16;
const RESUME: u8 = 17;
const COMMIT: u8 = 18;
const DRAIN: u8 = 19;
const READY: u8 = 20;
const PREPARED: u8 = 21;
const EXPORT_DONE: u8 = 22;
const ABORT: u8 = 23;
const RESTART_REQUESTED: u8 = 24;
const UPDATE_REQUESTED: u8 = 25;
const WITHDRAW: u8 = 26;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMessage {
    FreezeExport,
    Resume,
    Commit,
    Drain,
    Ready,
    Prepared,
    ExportDone,
    Abort,
    RestartRequested,
    UpdateRequested,
    /// Supervisor shutdown, phase one: withdraw readiness (health answers
    /// 503) but keep accepting for the lame-duck window; `Drain` follows.
    Withdraw,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DescriptorRole {
    Public(SocketAddr),
    AcmeHttp(SocketAddr),
    Admin(SocketAddr),
    Tcp(SocketAddr),
    WorkloadHttp(SocketAddr),
    ConfigLock,
    DockerLock,
    ConfigSnapshot,
}

#[derive(Debug)]
pub struct ReceivedDescriptor {
    pub role: DescriptorRole,
    pub fd: OwnedFd,
}

#[derive(Debug)]
pub enum ProtocolMessage {
    Control(ControlMessage),
    Descriptor(ReceivedDescriptor),
}

#[derive(Debug)]
pub struct ControlChannel {
    fd: OwnedFd,
}

pub fn control_channel() -> io::Result<(ControlChannel, ControlChannel)> {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` has room for the two fds written by socketpair.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socketpair returned two newly owned descriptors.
    let left = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: as above, and this descriptor is distinct from `left`.
    let right = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_send_timeout(left.as_fd(), Duration::from_secs(15))?;
    set_send_timeout(right.as_fd(), Duration::from_secs(15))?;
    Ok((ControlChannel { fd: left }, ControlChannel { fd: right }))
}

impl ControlChannel {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            fd: self.fd.try_clone()?,
        })
    }

    pub fn send_control(&self, message: ControlMessage) -> io::Result<()> {
        let mut frame = [0_u8; FRAME_LEN];
        frame[..MAGIC.len()].copy_from_slice(MAGIC);
        frame[8] = encode_control(message);
        send_frame(self.fd.as_fd(), &frame, None)
    }

    /// Queue a control without blocking an async request handler. A full
    /// supervisor channel is reported as `WouldBlock` so the caller can return
    /// a retryable response instead of occupying a runtime thread.
    pub fn try_send_control(&self, message: ControlMessage) -> io::Result<()> {
        let mut frame = [0_u8; FRAME_LEN];
        frame[..MAGIC.len()].copy_from_slice(MAGIC);
        frame[8] = encode_control(message);
        send_frame_with_flags(
            self.fd.as_fd(),
            &frame,
            None,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        )
    }

    pub fn send_descriptor(
        &self,
        role: DescriptorRole,
        descriptor: BorrowedFd<'_>,
    ) -> io::Result<()> {
        let frame = encode_descriptor(role);
        send_frame(self.fd.as_fd(), &frame, Some(descriptor))
    }

    pub fn recv_timeout(&self, timeout: Duration) -> io::Result<ProtocolMessage> {
        wait_readable(self.fd.as_fd(), timeout)?;
        receive_frame(self.fd.as_fd())
    }

    /// Receive a complete worker export using one total deadline. Protocol
    /// errors close every descriptor already received before returning.
    pub fn receive_export(&self, timeout: Duration) -> io::Result<Vec<ReceivedDescriptor>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid_data("handoff timeout is too large"))?;
        let mut descriptors = Vec::new();
        let mut roles = HashSet::new();
        let mut listener_addresses = HashSet::new();
        let mut public = false;
        let mut admin = false;
        let mut acme_http = false;
        let mut lock = false;
        let mut snapshot = false;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "handoff timed out"))?;
            match self.recv_timeout(remaining)? {
                ProtocolMessage::Descriptor(descriptor) => {
                    if descriptors.len() == MAX_HANDOFF_DESCRIPTORS {
                        return Err(invalid_data("too many handoff descriptors"));
                    }
                    if !roles.insert(descriptor.role) {
                        return Err(invalid_data("duplicate handoff descriptor role"));
                    }
                    match descriptor.role {
                        DescriptorRole::Public(address) => {
                            if public {
                                return Err(invalid_data("multiple public listeners in handoff"));
                            }
                            if !listener_addresses.insert(address) {
                                return Err(invalid_data("duplicate listener address in handoff"));
                            }
                            public = true;
                        }
                        DescriptorRole::Admin(address) => {
                            if admin {
                                return Err(invalid_data("multiple admin listeners in handoff"));
                            }
                            if !listener_addresses.insert(address) {
                                return Err(invalid_data("duplicate listener address in handoff"));
                            }
                            admin = true;
                        }
                        DescriptorRole::AcmeHttp(address) => {
                            if acme_http || !listener_addresses.insert(address) {
                                return Err(invalid_data("duplicate ACME listener in handoff"));
                            }
                            acme_http = true;
                        }
                        DescriptorRole::ConfigLock => lock = true,
                        DescriptorRole::DockerLock => {}
                        DescriptorRole::ConfigSnapshot => snapshot = true,
                        DescriptorRole::Tcp(address) | DescriptorRole::WorkloadHttp(address) => {
                            if !listener_addresses.insert(address) {
                                return Err(invalid_data("duplicate listener address in handoff"));
                            }
                        }
                    }
                    descriptors.push(descriptor);
                }
                ProtocolMessage::Control(ControlMessage::ExportDone) => {
                    if !(public && admin && snapshot) {
                        return Err(invalid_data(
                            "handoff requires one public listener, admin listener, and config snapshot",
                        ));
                    }
                    let _ = lock; // A file-backend worker exports it; SQL-mode workers may not.
                    return Ok(descriptors);
                }
                ProtocolMessage::Control(
                    ControlMessage::RestartRequested | ControlMessage::UpdateRequested,
                ) => {
                    // Admin requests can already be queued when the supervisor
                    // starts a handoff. The active transaction subsumes them.
                }
                ProtocolMessage::Control(_) => {
                    return Err(invalid_data("unexpected control message during fd export"));
                }
            }
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub fn into_owned_fd(self) -> OwnedFd {
        self.fd
    }

    /// Take ownership of a socket descriptor installed by a child's `pre_exec`
    /// hook. The descriptor is validated and immediately marked close-on-exec.
    ///
    /// # Safety
    ///
    /// `raw` must be an open descriptor owned by the caller and must not be used
    /// again after this call, whether validation succeeds or fails.
    pub unsafe fn from_child_fd(raw: RawFd) -> io::Result<Self> {
        // SAFETY: ownership requirements are delegated to the caller above.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        validate_seqpacket(fd.as_fd())?;
        set_cloexec(fd.as_fd(), true)?;
        Ok(Self { fd })
    }
}

/// Change close-on-exec state for the narrowly scoped descriptor installed in
/// a child by `pre_exec`. All received application descriptors remain CLOEXEC.
pub fn clear_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    set_cloexec(fd, false)
}

fn encode_control(message: ControlMessage) -> u8 {
    match message {
        ControlMessage::FreezeExport => FREEZE_EXPORT,
        ControlMessage::Resume => RESUME,
        ControlMessage::Commit => COMMIT,
        ControlMessage::Drain => DRAIN,
        ControlMessage::Ready => READY,
        ControlMessage::Prepared => PREPARED,
        ControlMessage::ExportDone => EXPORT_DONE,
        ControlMessage::Abort => ABORT,
        ControlMessage::RestartRequested => RESTART_REQUESTED,
        ControlMessage::UpdateRequested => UPDATE_REQUESTED,
        ControlMessage::Withdraw => WITHDRAW,
    }
}

fn decode_control(kind: u8) -> Option<ControlMessage> {
    Some(match kind {
        FREEZE_EXPORT => ControlMessage::FreezeExport,
        RESUME => ControlMessage::Resume,
        COMMIT => ControlMessage::Commit,
        DRAIN => ControlMessage::Drain,
        READY => ControlMessage::Ready,
        PREPARED => ControlMessage::Prepared,
        EXPORT_DONE => ControlMessage::ExportDone,
        ABORT => ControlMessage::Abort,
        RESTART_REQUESTED => ControlMessage::RestartRequested,
        UPDATE_REQUESTED => ControlMessage::UpdateRequested,
        WITHDRAW => ControlMessage::Withdraw,
        _ => return None,
    })
}

fn encode_descriptor(role: DescriptorRole) -> [u8; FRAME_LEN] {
    let mut frame = [0_u8; FRAME_LEN];
    frame[..MAGIC.len()].copy_from_slice(MAGIC);
    let address = match role {
        DescriptorRole::AcmeHttp(address) => {
            frame[8] = ACME_HTTP_FD;
            Some(address)
        }
        DescriptorRole::Public(address) => {
            frame[8] = PUBLIC_FD;
            Some(address)
        }
        DescriptorRole::Admin(address) => {
            frame[8] = ADMIN_FD;
            Some(address)
        }
        DescriptorRole::WorkloadHttp(address) => {
            frame[8] = WORKLOAD_HTTP_FD;
            Some(address)
        }
        DescriptorRole::Tcp(address) => {
            frame[8] = TCP_FD;
            Some(address)
        }
        DescriptorRole::ConfigLock => {
            frame[8] = CONFIG_LOCK_FD;
            None
        }
        DescriptorRole::DockerLock => {
            frame[8] = DOCKER_LOCK_FD;
            None
        }
        DescriptorRole::ConfigSnapshot => {
            frame[8] = CONFIG_SNAPSHOT_FD;
            None
        }
    };
    if let Some(address) = address {
        match address {
            SocketAddr::V4(address) => {
                frame[9] = 4;
                frame[10..12].copy_from_slice(&address.port().to_be_bytes());
                frame[20..24].copy_from_slice(&address.ip().octets());
            }
            SocketAddr::V6(address) => {
                frame[9] = 6;
                frame[10..12].copy_from_slice(&address.port().to_be_bytes());
                frame[12..16].copy_from_slice(&address.flowinfo().to_be_bytes());
                frame[16..20].copy_from_slice(&address.scope_id().to_be_bytes());
                frame[20..36].copy_from_slice(&address.ip().octets());
            }
        }
    }
    frame
}

fn decode_descriptor(frame: &[u8; FRAME_LEN]) -> io::Result<DescriptorRole> {
    let address = match frame[9] {
        4 => {
            if frame[12..20].iter().any(|byte| *byte != 0)
                || frame[24..].iter().any(|byte| *byte != 0)
            {
                return Err(invalid_data("nonzero reserved IPv4 handoff bytes"));
            }
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(frame[20], frame[21], frame[22], frame[23]),
                u16::from_be_bytes([frame[10], frame[11]]),
            ))
        }
        6 => {
            if frame[36..].iter().any(|byte| *byte != 0) {
                return Err(invalid_data("nonzero reserved IPv6 handoff bytes"));
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&frame[20..36]);
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                u16::from_be_bytes([frame[10], frame[11]]),
                u32::from_be_bytes(frame[12..16].try_into().expect("fixed slice")),
                u32::from_be_bytes(frame[16..20].try_into().expect("fixed slice")),
            ))
        }
        _ => return Err(invalid_data("invalid handoff address family")),
    };
    Ok(match frame[8] {
        ACME_HTTP_FD => DescriptorRole::AcmeHttp(address),
        PUBLIC_FD => DescriptorRole::Public(address),
        ADMIN_FD => DescriptorRole::Admin(address),
        TCP_FD => DescriptorRole::Tcp(address),
        WORKLOAD_HTTP_FD => DescriptorRole::WorkloadHttp(address),
        _ => return Err(invalid_data("invalid descriptor role")),
    })
}

fn send_frame(
    socket: BorrowedFd<'_>,
    frame: &[u8; FRAME_LEN],
    descriptor: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    send_frame_with_flags(socket, frame, descriptor, libc::MSG_NOSIGNAL)
}

fn send_frame_with_flags(
    socket: BorrowedFd<'_>,
    frame: &[u8; FRAME_LEN],
    descriptor: Option<BorrowedFd<'_>>,
    flags: libc::c_int,
) -> io::Result<()> {
    let mut iovec = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    // A usize array gives cmsghdr its required alignment.
    // SAFETY: this computes buffer space and does not dereference memory.
    let control_bytes = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as usize;
    let control_words = control_bytes.div_ceil(size_of::<usize>());
    let mut control = vec![0_usize; control_words];
    // SAFETY: all pointers refer to live buffers for the duration of sendmsg.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    if let Some(descriptor) = descriptor {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() * size_of::<usize>();
        // SAFETY: the control buffer was sized with CMSG_SPACE for one RawFd.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as usize;
            ptr::write(
                libc::CMSG_DATA(header).cast::<RawFd>(),
                descriptor.as_raw_fd(),
            );
        }
    }
    loop {
        // SAFETY: message and all referenced buffers are initialized above.
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, flags) };
        if sent == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if sent as usize != frame.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short supervisor protocol write",
            ));
        }
        return Ok(());
    }
}

fn receive_frame(socket: BorrowedFd<'_>) -> io::Result<ProtocolMessage> {
    let mut frame = [0_u8; FRAME_LEN];
    let mut iovec = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    // SAFETY: this computes buffer space and does not dereference memory.
    let control_bytes = unsafe { libc::CMSG_SPACE((size_of::<RawFd>() * 2) as _) } as usize;
    let control_words = control_bytes.div_ceil(size_of::<usize>());
    let mut control = vec![0_usize; control_words];
    // SAFETY: zero is a valid initial state for msghdr, completed below.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len() * size_of::<usize>();
    let received = loop {
        // SAFETY: message points at writable frame and control buffers.
        let result =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        break result as usize;
    };

    let descriptors = received_descriptors(&message)?;
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(invalid_data("truncated supervisor protocol message"));
    }
    if received != FRAME_LEN {
        return Err(invalid_data("invalid supervisor protocol frame length"));
    }
    if &frame[..MAGIC.len()] != MAGIC {
        return Err(invalid_data("invalid supervisor protocol magic"));
    }

    match frame[8] {
        PUBLIC_FD | ADMIN_FD | TCP_FD | ACME_HTTP_FD | WORKLOAD_HTTP_FD => {
            if descriptors.len() != 1 {
                return Err(invalid_data("descriptor frame must carry exactly one fd"));
            }
            let role = decode_descriptor(&frame)?;
            Ok(ProtocolMessage::Descriptor(ReceivedDescriptor {
                role,
                fd: descriptors.into_iter().next().expect("one descriptor"),
            }))
        }
        CONFIG_LOCK_FD | CONFIG_SNAPSHOT_FD | DOCKER_LOCK_FD => {
            if frame[9..].iter().any(|byte| *byte != 0) {
                return Err(invalid_data("config-lock frame contains reserved data"));
            }
            if descriptors.len() != 1 {
                return Err(invalid_data("descriptor frame must carry exactly one fd"));
            }
            Ok(ProtocolMessage::Descriptor(ReceivedDescriptor {
                role: match frame[8] {
                    CONFIG_LOCK_FD => DescriptorRole::ConfigLock,
                    DOCKER_LOCK_FD => DescriptorRole::DockerLock,
                    _ => DescriptorRole::ConfigSnapshot,
                },
                fd: descriptors.into_iter().next().expect("one descriptor"),
            }))
        }
        kind => {
            if frame[9..].iter().any(|byte| *byte != 0) {
                return Err(invalid_data("control frame contains reserved data"));
            }
            if !descriptors.is_empty() {
                return Err(invalid_data(
                    "control frame unexpectedly carried a descriptor",
                ));
            }
            let control = decode_control(kind)
                .ok_or_else(|| invalid_data("unknown supervisor control message"))?;
            Ok(ProtocolMessage::Control(control))
        }
    }
}

fn received_descriptors(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let mut descriptors = Vec::new();
    // SAFETY: recvmsg initialized the ancillary chain inside message's buffer.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        // SAFETY: header is part of the validated cmsghdr chain from libc.
        let current = unsafe { &*header };
        if current.cmsg_level != libc::SOL_SOCKET || current.cmsg_type != libc::SCM_RIGHTS {
            return Err(invalid_data("unexpected supervisor ancillary message"));
        }
        // SAFETY: this computes the fixed cmsghdr length.
        let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
        if current.cmsg_len < header_length {
            return Err(invalid_data("invalid SCM_RIGHTS length"));
        }
        let bytes = current.cmsg_len - header_length;
        if bytes == 0 || !bytes.is_multiple_of(size_of::<RawFd>()) {
            return Err(invalid_data("invalid SCM_RIGHTS descriptor data"));
        }
        let count = bytes / size_of::<RawFd>();
        for index in 0..count {
            // SAFETY: the cmsg length proves this indexed RawFd is present.
            let raw = unsafe { ptr::read(libc::CMSG_DATA(header).cast::<RawFd>().add(index)) };
            // SAFETY: each fd received through SCM_RIGHTS is newly owned here.
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            set_cloexec(descriptor.as_fd(), true)?;
            descriptors.push(descriptor);
        }
        // SAFETY: advances within recvmsg's ancillary buffer or returns null.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok(descriptors)
}

fn wait_readable(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid_data("handoff timeout is too large"))?;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "handoff timed out"))?;
        let milliseconds = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points at one initialized entry.
        let result = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if result == 0 {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "handoff timed out"));
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if pollfd.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "supervisor channel closed",
        ));
    }
}

fn validate_seqpacket(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut socket_type = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: socket_type and length are valid output pointers for getsockopt.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if socket_type != libc::SOCK_SEQPACKET {
        return Err(invalid_data("child handoff fd is not SOCK_SEQPACKET"));
    }
    Ok(())
}

fn set_cloexec(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    // SAFETY: F_GETFD does not mutate memory and fd is live.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: F_SETFD accepts the integer flag set returned by F_GETFD.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_send_timeout(fd: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
    let value = libc::timeval {
        tv_sec: timeout.as_secs().try_into().unwrap_or(libc::time_t::MAX),
        tv_usec: timeout.subsec_micros().into(),
    };
    // SAFETY: value is a valid timeval and its size is passed exactly.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&value as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
