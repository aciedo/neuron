use std::{io, net::SocketAddr, sync::Arc};

use quinn::ConnectError;
use quinn::ConnectError::{InvalidDnsName, InvalidRemoteAddress};
use quinn::ConnectionError::{ApplicationClosed, ConnectionClosed, TransportError};
use quinn_proto::transport_parameters as QError;
use rustls::Error as RlsError;

use quinn::{ApplicationClose, ConnectionClose, ConnectionError};
use rustls::ServerConfig;

struct Endpoint {
    endpoint: quinn::Endpoint,
    client_config: Arc<rustls::ClientConfig>,
}

pub enum ConnectingError {
    RustlsError(rustls::Error),

    EndpointStopping,
    TooManyConnections,
    InvalidDnsName(String),
    InvalidRemoteAddress(SocketAddr),
    NoDefaultClientConfig,
    UnsupportedVersion,

    VersionMismatch,
    TransportError(RlsError),
    ConnectionClosed(ConnectionClose),
    ApplicationClosed(ApplicationClose),
    Reset,
    TimedOut,
    LocallyClosed,
}

impl From<ConnectError> for ConnectingError {
    fn from(error: ConnectError) -> Self {
        match error {
            EndpointStopping => return ConnectingError::EndpointStopping,
            TooManyConnections => return ConnectingError::TooManyConnections,
            InvalidDnsName(String) => return ConnectingError::InvalidDnsName(String),
            InvalidRemoteAddress(SocketAddr) => {
                return ConnectingError::InvalidRemoteAddress(SocketAddr)
            }
            NoDefaultClientConfig => return ConnectingError::NoDefaultClientConfig,
            UnsupportedVersion => return ConnectingError::UnsupportedVersion,
        }
    }
}

impl From<ConnectionError> for ConnectingError {
    fn from(error: ConnectionError) -> Self {
        match error {
            VersionMismatch => return ConnectingError::VersionMismatch,
            TransportError(Error) => return ConnectingError::TransportError(RlsError),
            ConnectionClosed(ConnectionClose) => {
                return ConnectingError::ConnectionClosed(ConnectionClose)
            }
            ApplicationClosed(ApplicationClose) => {
                return ConnectingError::ApplicationClosed(ApplicationClose)
            }
            Reset => return ConnectingError::Reset,
            TimedOut => return ConnectingError::TimedOut,
            LocallyClosed => return ConnectingError::LocallyClosed,
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
