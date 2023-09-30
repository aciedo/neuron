use std::{io, net::SocketAddr, sync::Arc};

use quinn::{ConnectError, ConnectionError};
use quinn_proto::{ApplicationClose, ConnectionClose, TransportError};
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
    TransportError(TransportError),
    ConnectionClosed(ConnectionClose),
    ApplicationClosed(ApplicationClose),
    Reset,
    TimedOut,
    LocallyClosed,
}

impl From<ConnectError> for ConnectingError {
    fn from(error: ConnectError) -> Self {
        match error {
            ConnectError::EndpointStopping => ConnectingError::EndpointStopping,
            ConnectError::TooManyConnections => ConnectingError::TooManyConnections,
            ConnectError::InvalidDnsName(name) => ConnectingError::InvalidDnsName(name),
            ConnectError::InvalidRemoteAddress(socket_addr) => {
                ConnectingError::InvalidRemoteAddress(socket_addr)
            }
            ConnectError::NoDefaultClientConfig => ConnectingError::NoDefaultClientConfig,
            ConnectError::UnsupportedVersion => ConnectingError::UnsupportedVersion,
        }
    }
}

impl From<ConnectionError> for ConnectingError {
    fn from(error: ConnectionError) -> Self {
        match error {
            ConnectionError::VersionMismatch => ConnectingError::VersionMismatch,
            ConnectionError::TransportError(e) => ConnectingError::TransportError(e),
            ConnectionError::ConnectionClosed(close_frame) => {
                ConnectingError::ConnectionClosed(close_frame)
            }
            ConnectionError::ApplicationClosed(close_frame) => {
                ConnectingError::ApplicationClosed(close_frame)
            }
            ConnectionError::Reset => ConnectingError::Reset,
            ConnectionError::TimedOut => ConnectingError::TimedOut,
            ConnectionError::LocallyClosed => ConnectingError::LocallyClosed,
        }
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
        Ok(Endpoint {
            endpoint: quinn::Endpoint::server(server_config, socket_addr)?,
            client_config,
        })
    }

    pub fn connect(socket_addr: SocketAddr, server_name: &str) -> Result<(), ConnectingError> {
        todo!();
    }
}
