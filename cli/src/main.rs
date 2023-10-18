use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use blake3::hash;
use hashbrown::{HashMap, HashSet};
use kt2::Keypair;
use neuron::router::net::endpoint::Endpoint;
use rkyv::to_bytes;

use neuron::router::net::ski::{
    Certificate, Host, RouterIdentityService, ServiceIdentity,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let ca_kp = Keypair::generate(None);
    let ca_pk = ca_kp.public;
    let ca_sk = ca_kp.secret;
    let root_ca = Certificate::builder()
        .hosts(HashMap::new())
        .human_readable_name("root-ca".into())
        .id(hash(&ca_pk.bytes).into())
        .public_key(ca_pk)
        .tags(vec![])
        .build();

    let ep1 = {
        let mut hosts = HashMap::new();
        hosts.insert(Host::IPv4([127, 0, 0, 1]), HashSet::new());
        let Keypair { public, secret } = Keypair::generate(None);
        let cert = Certificate::builder()
            .hosts(hosts)
            .human_readable_name("test".into())
            .id(hash(&public.bytes).into())
            .public_key(public)
            .tags(vec![])
            .build();
        println!("{}", cert);
        let identity = ServiceIdentity {
            cert: cert.clone(),
            signature: ca_sk.sign(&to_bytes::<_, 1024>(&cert).unwrap()),
        };
        let id_service = Arc::new(
            RouterIdentityService::new(identity, secret, root_ca.clone())
                .unwrap(),
        );
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), id_service)
            .unwrap()
    };

    let ep2 = {
        let mut hosts = HashMap::new();
        hosts.insert(Host::IPv4([127, 0, 0, 2]), HashSet::new());
        let Keypair { public, secret } = Keypair::generate(None);
        let cert = Certificate::builder()
            .hosts(hosts)
            .human_readable_name("test".into())
            .id(hash(&public.bytes).into())
            .public_key(public)
            .tags(vec![])
            .build();
        println!("{}", cert);
        let identity = ServiceIdentity {
            cert: cert.clone(),
            signature: ca_sk.sign(&to_bytes::<_, 1024>(&cert).unwrap()),
        };
        let id_service = Arc::new(
            RouterIdentityService::new(identity, secret, root_ca).unwrap(),
        );
        Endpoint::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), id_service)
            .unwrap()
    };

    ep1.connect(
        std::net::SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 2),
            471,
        )),
        "127.0.0.2",
    )
    .await
    .unwrap();

    loop {}
}
