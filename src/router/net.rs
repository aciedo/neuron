use std::{io, net::SocketAddr, sync::Arc};

use quinn::ConnectError;
use quinn::ConnectError::{InvalidDnsName, InvalidRemoteAddress};
use quinn::{ApplicationClose, ConnectionClose, ConnectionError};
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
    TransportError(rustls::Error),
    ConnectionClosed(ConnectionClose),
    ApplicationClosed(ApplicationClose),
    Reset,
    TimedOut,
    LocallyClosed,
}

impl From<ConnectError> for ConnectingError {
    fn from(error: ConnectError) -> Self {
        match error {
            EndpointStopping => ConnectingError::EndpointStopping,
            TooManyConnections => ConnectingError::TooManyConnections,
            InvalidDnsName(string) => ConnectingError::InvalidDnsName(string),
            InvalidRemoteAddress(socket_addr) => ConnectingError::InvalidRemoteAddress(socket_addr),
            NoDefaultClientConfig => ConnectingError::NoDefaultClientConfig,
            UnsupportedVersion => ConnectingError::UnsupportedVersion,
        }
    }
}

impl From<ConnectionError> for ConnectingError {
    fn from(error_enum: ConnectionError) -> Self {
        match error_enum {
            ConnectionError::VersionMismatch => ConnectingError::VersionMismatch,
            ConnectionError::TransportError(inner_error) => {
                ConnectingError::TransportError(inner_error)
            }
            ConnectionError::ConnectionClosed(connection_close) => {
                ConnectingError::ConnectionClosed(connection_close)
            }
            ConnectionError::ApplicationClosed(application_close) => {
                ConnectingError::ApplicationClosed(application_close)
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
