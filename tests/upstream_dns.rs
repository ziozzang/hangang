use hangang::upstream_dns::resolve;
use hickory_resolver::proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::net::UdpSocket;

async fn dns(
    ip: Ipv4Addr,
    ttl: u32,
    negative: bool,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            c.fetch_add(1, Ordering::Relaxed);
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut a = Message::response(q.metadata.id, q.metadata.op_code);
            a.metadata.recursion_desired = true;
            a.metadata.recursion_available = true;
            for query in &q.queries {
                a.add_query(query.clone());
                if !negative && query.query_type() == RecordType::A {
                    a.add_answer(Record::from_rdata(
                        query.name().clone(),
                        ttl,
                        RData::A(A(ip)),
                    ));
                }
            }
            if negative {
                a.metadata.response_code = ResponseCode::NXDomain;
            }
            socket.send_to(&a.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (addr, count, task)
}
#[tokio::test]
async fn explicit_servers_are_isolated_cached_and_ttl_bounded() {
    let (a, ca, ta) = dns(Ipv4Addr::new(127, 0, 0, 2), 60, false).await;
    let (b, _, tb) = dns(Ipv4Addr::new(127, 0, 0, 3), 60, false).await;
    assert_eq!(
        resolve("selected.test", &[a]).await.unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]
    );
    let queries = ca.load(Ordering::Relaxed);
    assert_eq!(
        resolve("SELECTED.test", &[a]).await.unwrap()[0],
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
    );
    assert_eq!(ca.load(Ordering::Relaxed), queries);
    assert_eq!(
        resolve("selected.test", &[b]).await.unwrap()[0],
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))
    );
    ta.abort();
    tb.abort();
}
#[tokio::test]
async fn negative_answer_does_not_use_hosts_file_or_system_dns() {
    let (a, _, task) = dns(Ipv4Addr::LOCALHOST, 0, true).await;
    assert!(resolve("public.example", &[a]).await.is_err());
    assert!(resolve("localhost", &[a]).await.is_err());
    assert_eq!(
        resolve("127.0.0.7", &[a]).await.unwrap(),
        vec!["127.0.0.7".parse::<IpAddr>().unwrap()]
    );
    task.abort();
}
#[tokio::test]
async fn zero_ttl_is_not_retained_and_timeout_is_bounded() {
    let (a, c, task) = dns(Ipv4Addr::LOCALHOST, 0, false).await;
    resolve("uncached.test", &[a]).await.unwrap();
    let first = c.load(Ordering::Relaxed);
    resolve("uncached.test", &[a]).await.unwrap();
    assert!(c.load(Ordering::Relaxed) > first);
    task.abort();
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(2500),
            resolve("silent.test", &[silent.local_addr().unwrap()])
        )
        .await
        .unwrap()
        .is_err()
    );
}

#[tokio::test]
async fn truncated_udp_answer_retries_tcp_on_the_selected_endpoint() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let ut = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut a = Message::response(q.metadata.id, q.metadata.op_code);
            a.metadata.truncation = true;
            a.metadata.recursion_available = true;
            for question in &q.queries {
                a.add_query(question.clone());
            }
            udp.send_to(&a.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    let tt = tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let c = c.clone();
            tokio::spawn(async move {
                while let Ok(len) = stream.read_u16().await {
                    let mut buf = vec![0; len as usize];
                    if stream.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    let q = Message::from_vec(&buf).unwrap();
                    let mut a = Message::response(q.metadata.id, q.metadata.op_code);
                    a.metadata.recursion_available = true;
                    for question in &q.queries {
                        a.add_query(question.clone());
                        if question.query_type() == RecordType::A {
                            a.add_answer(Record::from_rdata(
                                question.name().clone(),
                                30,
                                RData::A(A(Ipv4Addr::new(127, 0, 0, 8))),
                            ));
                        }
                    }
                    let bytes = a.to_vec().unwrap();
                    c.fetch_add(1, Ordering::Relaxed);
                    if stream.write_u16(bytes.len() as u16).await.is_err() {
                        break;
                    }
                    if stream.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    assert_eq!(
        resolve("tcp-fallback.test", &[addr]).await.unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8))]
    );
    assert!(count.load(Ordering::Relaxed) > 0);
    ut.abort();
    tt.abort();
}
