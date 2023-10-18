use std::net::{IpAddr, SocketAddr};

pub mod axon;
pub mod endpoint;
pub mod error;
pub mod netwatch;
pub mod ski;
pub mod wire;

/// Converts an IP address and port to a socket address.
fn ip_addr_to_socket_addr(ip: IpAddr, port: u16) -> SocketAddr {
    match ip {
        IpAddr::V4(ip) => SocketAddr::from((ip, port)),
        IpAddr::V6(ip) => SocketAddr::from((ip, port)),
    }
}

const NEURON_PORT: u16 = 471; // "NEURON" in ascii, summed
const SKI_ROOT_CA: &[u8] = include_bytes!("ski.crt");
