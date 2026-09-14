#![cfg(unix)]

use hangang::restart::{ControlMessage, DescriptorRole, ProtocolMessage, control_channel};
use std::{
    fs::File,
    net::{Ipv4Addr, SocketAddr, TcpListener},
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};

fn listener() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    (listener, address)
}

#[test]
fn transfers_typed_descriptors_with_cloexec_and_control_messages() {
    let (sender, receiver) = control_channel().unwrap();
    let (public, public_address) = listener();
    let (admin, admin_address) = listener();
    let (tcp, tcp_address) = listener();
    let (workload, workload_address) = listener();
    let (named_public, named_public_address) = listener();
    let snapshot = tempfile::tempfile().unwrap();
    let lock = tempfile::tempfile().unwrap();
    let docker_lock = tempfile::tempfile().unwrap();

    let thread = std::thread::spawn(move || {
        sender
            .send_descriptor(DescriptorRole::Public(public_address), public.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::Admin(admin_address), admin.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::Tcp(tcp_address), tcp.as_fd())
            .unwrap();
        sender
            .send_descriptor(
                DescriptorRole::WorkloadHttp(workload_address),
                workload.as_fd(),
            )
            .unwrap();
        sender
            .send_descriptor(
                DescriptorRole::PublicHttp(named_public_address),
                named_public.as_fd(),
            )
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::ConfigSnapshot, snapshot.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::ConfigLock, lock.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::DockerLock, docker_lock.as_fd())
            .unwrap();
        sender.send_control(ControlMessage::ExportDone).unwrap();
        sender.send_control(ControlMessage::Prepared).unwrap();
    });

    let received = receiver.receive_export(Duration::from_secs(1)).unwrap();
    assert_eq!(received.len(), 8);
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::PublicHttp(named_public_address))
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::WorkloadHttp(workload_address))
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::Public(public_address))
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::Admin(admin_address))
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::Tcp(tcp_address))
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::ConfigSnapshot)
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::ConfigLock)
    );
    assert!(
        received
            .iter()
            .any(|item| item.role == DescriptorRole::DockerLock)
    );
    for item in &received {
        // SAFETY: F_GETFD only inspects this live descriptor.
        let flags = unsafe { libc::fcntl(item.fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
        ProtocolMessage::Control(ControlMessage::Prepared)
    ));
    thread.join().unwrap();
}

#[test]
fn export_rejects_a_second_public_category_even_at_another_address() {
    let (sender, receiver) = control_channel().unwrap();
    let (first, first_address) = listener();
    let (second, second_address) = listener();
    let thread = std::thread::spawn(move || {
        sender
            .send_descriptor(DescriptorRole::Public(first_address), first.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::Public(second_address), second.as_fd())
            .unwrap();
    });
    let error = receiver.receive_export(Duration::from_secs(1)).unwrap_err();
    assert!(error.to_string().contains("public"));
    thread.join().unwrap();
}

#[test]
fn readiness_receive_has_a_real_timeout() {
    let (_sender, receiver) = control_channel().unwrap();
    let started = std::time::Instant::now();
    let error = receiver
        .recv_timeout(Duration::from_millis(20))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn request_controls_are_coalesced_during_an_active_export() {
    let (sender, receiver) = control_channel().unwrap();
    let (public, public_address) = listener();
    let (admin, admin_address) = listener();
    let snapshot = File::open("/dev/null").unwrap();
    let thread = std::thread::spawn(move || {
        sender
            .send_control(ControlMessage::RestartRequested)
            .unwrap();
        sender
            .send_control(ControlMessage::UpdateRequested)
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::Public(public_address), public.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::Admin(admin_address), admin.as_fd())
            .unwrap();
        sender
            .send_descriptor(DescriptorRole::ConfigSnapshot, snapshot.as_fd())
            .unwrap();
        sender.send_control(ControlMessage::ExportDone).unwrap();
    });
    let descriptors = receiver.receive_export(Duration::from_secs(1)).unwrap();
    assert_eq!(descriptors.len(), 3);
    thread.join().unwrap();
}
