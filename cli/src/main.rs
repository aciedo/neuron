use std::net::SocketAddr::V4;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use blake3::hash;
use hashbrown::{HashMap, HashSet};
use kt2::{Keypair, SecretKey};
use neuron::router::net::endpoint::Endpoint;
use rkyv::to_bytes;

use neuron::router::net::ski::{
    Certificate, Host, RouterIdentityService, ServiceIdentity,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    const TOTAL: usize = 7;

    let ca_kp = Keypair::generate(None);
    let ca_pk = ca_kp.public;
    let ca_sk = ca_kp.secret;
    let root_ca = Certificate::builder()
        .hosts(HashMap::new())
        .human_readable_name("root-ca".into())
        .id(hash(&ca_pk.bytes).as_bytes()[0..4].try_into().unwrap())
        .public_key(ca_pk)
        .tags(vec![])
        .build();

    let mut eps = vec![];
    for i in 1..TOTAL + 1 {
        eps.push(create_ep([127, 0, 0, i as u8], &ca_sk, &root_ca))
    }

    for i in 0..TOTAL {
        let ep_from = &eps[i];
        let ip_to = [127, 0, 0, ((i + 1) % TOTAL + 1) as u8];
        let addr_to = V4(SocketAddrV4::new(
            Ipv4Addr::new(ip_to[0], ip_to[1], ip_to[2], ip_to[3]),
            471,
        ));
        ep_from
            .connect(addr_to, &format!("127.0.0.{}", (i + 1) % TOTAL + 1))
            .await
            .unwrap();
    }

    loop {}
}

fn create_ep(
    ip: [u8; 4],
    ca_sk: &SecretKey,
    root_ca: &Certificate,
) -> Endpoint {
    let mut hosts = HashMap::new();
    hosts.insert(Host::IPv4(ip.clone()), HashSet::new());
    let Keypair { public, secret } = Keypair::generate(None);
    let cert = Certificate::builder()
        .hosts(hosts)
        .human_readable_name(ip.map(|byte| byte.to_string()).join("."))
        .id(hash(&public.bytes).as_bytes()[0..4].try_into().unwrap())
        .public_key(public)
        .tags(vec![])
        .build();
    println!("{}", cert);
    let identity = ServiceIdentity {
        cert: cert.clone(),
        signature: ca_sk.sign(&to_bytes::<_, 1024>(&cert).unwrap()),
    };
    let id_service = Arc::new(
        RouterIdentityService::new(identity, secret, (*root_ca).clone())
            .unwrap(),
    );
    Endpoint::new(
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        id_service,
    )
    .unwrap()
}
