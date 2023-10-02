use std::{io, net::SocketAddr, sync::Arc};

use quinn::{ConnectError, ConnectionError, Connecting, default_runtime};
use quinn_proto::{ApplicationClose, ConnectionClose, TransportError};
use rustls::ServerConfig;

struct Endpoint {
    ep: Arc<quinn::Endpoint>,
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

    Error,

    WriteError,
    ReadToEndError,
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

impl From<std::io::Error> for ConnectingError {
    fn from(value: std::io::Error) -> Self {
        match value {
            Error => ConnectingError::Error,
        }
    }
}

impl From<quinn::WriteError> for ConnectingError {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            WriteError => ConnectingError::WriteError,
        }
    }
}

impl From<quinn::ReadToEndError> for ConnectingError {
    fn from(value: quinn::ReadToEndError) -> Self {
        match value {
            ReadToEndError => ConnectingError::ReadToEndError,
        }
    }
}

impl Endpoint {
    /// Creates a new QUIC endpoint bound to the given socket address with the given TLS configuration.
    pub fn new(
        socket_addr: SocketAddr,
        server_tls: rustls::ServerConfig,
        client_tls: Arc<rustls::ClientConfig>,
    ) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(socket_addr)?;
        let runtime = default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        
        // shared transport configuration for the server and client sides
        // this is the default config with the BBR congestion controller enabled
        let mut transport_config = quinn::TransportConfig::default();
        let bbr_config = quinn::congestion::BbrConfig::default();
        transport_config.congestion_controller_factory(Arc::new(bbr_config));
        let transport_config = Arc::new(transport_config);
        
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_tls));
        server_config.transport_config(transport_config.clone());
        
        let mut client_config = quinn::ClientConfig::new(client_tls);
        client_config.transport_config(transport_config);
        
        let config = quinn::EndpointConfig::default();
        let mut ep = quinn::Endpoint::new(config, Some(server_config), socket, runtime)?;
        ep.set_default_client_config(client_config);
        
        let ep = Arc::new(ep);
        tokio::spawn(Self::acceptor(ep.clone()));
        Ok(Endpoint { ep })
    }

    /// Makes an outbound connection from this endpoint to another NEURON node.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        config: quinn::ServerConfig,
    ) -> Result<(), ConnectingError> {
        let conn = self.ep.connect(addr, server_name)?.await?;
        Ok(())
    }
    
    /// Accepts incoming connections and spawns tasks to handle them.
    /// This will run until the endpoint is shut down, so it should be spawned in a dedicated task.
    pub async fn acceptor(ep: Arc<quinn::Endpoint>) -> Result<(), ConnectingError> {
        while let Some(conn) = ep.accept().await {
            tokio::spawn(async move {
                if let Err(e) = Self::connection_handler(conn).await {
                    println!("Connection failed: {:?}", e);
                }
            });
        }
        Ok(())
    }
    
    /// Handles an incoming connection.
    pub async fn connection_handler(conn: Connecting) -> Result<(), ()> {
        if let Ok(conn) = conn.await {
            let conn_id = conn.stable_id();
            // connections are bi-directional
        }
        Ok(())
    }
}
