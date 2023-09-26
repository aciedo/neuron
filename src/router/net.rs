use std::{io, sync::Arc, net::SocketAddr};

use rustls::ServerConfig;

struct Endpoint {
    endpoint: quinn::Endpoint,
    client_config: Arc<rustls::ClientConfig>,
}

pub enum ConnectingError {
    EndpointStopping,
    TooManyConnections,
    InvalidDnsName(String),
    InvalidRemoteAddress(SocketAddr),
    NoDefaultClientConfig,
    UnsupportedVersion,
    VersionMismatch,
    TransportError(Error),
    ConnectionClosed(ConnectionClose),
    ApplicationClosed(ApplicationClose),
    Reset,
    TimedOut,
    LocallyClosed,
}

impl From<ConnectError> for ConnectingError {
    use ConnectError as ce;
    use ConnectionError as cte;
    fn from(error: ConnectionError) -> Self {
        match error 
    }
}



impl Endpoint {
    /// Creates a new QUIC endpoint bound to the given socket address with the given TLS configuration.
    pub fn new(
        tls: ServerConfig, 
        socket_addr: SocketAddr,
        client_config: Arc<rustls::ClientConfig>,
    ) -> io::Result<Self> {
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(tls));
        Ok(Endpoint { endpoint: quinn::Endpoint::server(server_config, socket_addr)?, client_config })
    }
    
    pub fn connect(socket_addr: SocketAddr, server_name: &str) -> () {
        
    }
}