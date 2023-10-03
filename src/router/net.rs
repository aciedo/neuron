use std::{
    io::{self, BufReader, Cursor},
    net::{SocketAddr, IpAddr, UdpSocket},
    sync::Arc, time::Duration,
};

use hashbrown::HashMap;
use quinn::{default_runtime, ConnectError, Connecting, ConnectionError};
use quinn_proto::{ApplicationClose, ConnectionClose, TransportError};
use rkyv::{Archive, Deserialize, Serialize};
use rustls::{
    internal::msgs::codec::Codec, server::AllowAnyAuthenticatedClient,
    Certificate, PrivateKey,
};
use tokio::{sync::RwLock, time::interval};

const SKI_ROOT_CA: &[u8] = include_bytes!("ski.crt");

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
            ConnectError::TooManyConnections => {
                ConnectingError::TooManyConnections
            }
            ConnectError::InvalidDnsName(name) => {
                ConnectingError::InvalidDnsName(name)
            }
            ConnectError::InvalidRemoteAddress(socket_addr) => {
                ConnectingError::InvalidRemoteAddress(socket_addr)
            }
            ConnectError::NoDefaultClientConfig => {
                ConnectingError::NoDefaultClientConfig
            }
            ConnectError::UnsupportedVersion => {
                ConnectingError::UnsupportedVersion
            }
        }
    }
}

impl From<ConnectionError> for ConnectingError {
    fn from(error: ConnectionError) -> Self {
        match error {
            ConnectionError::VersionMismatch => {
                ConnectingError::VersionMismatch
            }
            ConnectionError::TransportError(e) => {
                ConnectingError::TransportError(e)
            }
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

const NEURON_PORT: u16 = 471; // "NEURON" in ascii, summed

struct Endpoint {
    ep: Arc<quinn::Endpoint>,
    axons: Arc<RwLock<HashMap<usize, Axon>>>
}

impl Endpoint {
    /// Creates a new QUIC endpoint bound to the given socket address with the
    /// given TLS configuration.
    pub fn new(
        ip_addr: IpAddr,
        key: &[u8],
        cert: &[u8],
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(ip_addr_to_socket_addr(ip_addr, NEURON_PORT))?;
        let runtime = default_runtime().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no async runtime found")
        })?;

        let (client_tls, server_tls) = Self::tls_config(cert, key).unwrap();

        // shared transport configuration for the server and client sides
        // this is the default config with the BBR congestion controller enabled
        let mut transport_config = quinn::TransportConfig::default();
        let bbr_config = quinn::congestion::BbrConfig::default();
        transport_config.congestion_controller_factory(Arc::new(bbr_config));
        let transport_config = Arc::new(transport_config);

        let mut server_config =
            quinn::ServerConfig::with_crypto(Arc::new(server_tls));
        server_config.transport_config(transport_config.clone());

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_tls));
        client_config.transport_config(transport_config);

        let config = quinn::EndpointConfig::default();
        let mut ep =
            quinn::Endpoint::new(config, Some(server_config), socket, runtime)?;
        ep.set_default_client_config(client_config);

        let ep = Arc::new(ep);
        tokio::spawn(Self::acceptor(ep.clone()));
        Ok(Endpoint { 
            ep,
            axons: Arc::new(RwLock::new(HashMap::new()))
        })
    }

    // /// Creates an outbound axon from this endpoint to another NEURON node.
    // pub async fn connect(
    //     &self,
    //     addr: SocketAddr,
    //     server_name: &str,
    //     config: quinn::ServerConfig,
    // ) -> Result<(), ConnectingError> {
    //     let axon = self.ep.connect(addr, server_name)?.await?;

    //     // heartbeat stream
    //     // send is moved to a basic task that sends heartbeats at a regular
    //     // interval receive is moved to a more advanced task that
    //     // handles measuring all axons' quality which is responsible for
    //     // triggering leader elections and optimising routing
    //     let (hb_send, hb_receive) = axon.open_bi().await?;
    //     // control streams manage higher level neuron metadata and routing info,
    //     // such as a add/remove router, add/remove region, etc
    //     // this control channel isn't generally very busy, so these two are
    //     // handled in the same task
    //     let (ctrl_send, ctrl_receive) = axon.open_bi().await?;

    //     // axons support multiple {bi/uni}directional streams which are
    //     // prioritized and handled asynchronously neuron maintains
    //     // streams in this order of priority:
    //     // 0. heartbeat stream (bi-directional)
    //     //    - responsible for sending and receiving heartbeat messages
    //     //    - measure latency and assist axon quality and routing information
    //     // 1. control stream (bi-directional)
    //     //    - responsible for neuron's network metadata
    //     //    - such as new router information
    //     // 2... dynamically created per-partition data streams (uni-directional
    //     // due to number of partitions)
    //     //    - responsible for handling writing and reading
    //     //    - created dynamically as they are inexpensive to create and allow
    //     //      for efficient parallelism
    //     //    - may reach up to 65536 streams in total per axon
    //     //    - each stream is assigned a partition
    //     //    - each partition handler owns its own stream - it won't block
    //     //      other partitions
    //     //    - each partition has a pair of unidirectional channels for each
    //     //      axon
    //     //
    //     Ok(())
    // }

    /// Accepts incoming axons and spawns tasks to handle them.
    /// This will run until the endpoint is shut down, so it should be spawned
    /// in a dedicated task.
    async fn acceptor(
        ep: Arc<quinn::Endpoint>,
    ) -> Result<(), ConnectingError> {
        while let Some(in_progress) = ep.accept().await {
            tokio::spawn(Axon::new(in_progress));
        }
        Ok(())
    }
    
    pub async fn connect(&self, remote: SocketAddr, remote_name: &str) -> Result<(), ConnectingError> {
        let axon = Axon::new(self.ep.connect(remote, remote_name)?).await?;
        self.axons.write().await.insert(axon.id(), axon);
        Ok(())
    }

    /// Returns rustls configurations using SKI's root CA.
    /// Both client and server validate each other using the root CA.
    fn tls_config(
        cert: &[u8],
        key: &[u8],
    ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), rustls::Error>
    {
        let root_ca = Certificate::read_bytes(SKI_ROOT_CA)?;
        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.add(&root_ca)?;

        let cert = Certificate::read_bytes(cert)?;
        let key = {
            let mut keys = rustls_pemfile::pkcs8_private_keys(
                &mut BufReader::new(Cursor::new(key)),
            )
            .unwrap();
            if keys.len() != 1 {
                panic!("expected exactly one private key");
            }
            keys.remove(0)
        };

        let client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_certs.clone())
            .with_client_auth_cert(
                vec![cert.clone()],
                PrivateKey(key.clone()),
            )?;

        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(
                // TODO: use a custom verifier that checks the client's
                // certificate against the root CA, including host name, role
                // checks etc ensure that the client is an
                // actual neuron router
                AllowAnyAuthenticatedClient::new(root_certs).boxed(),
            )
            .with_single_cert(vec![cert], PrivateKey(key))?;

        Ok((client_config, server_config))
    }
}

fn ip_addr_to_socket_addr(ip: IpAddr, port: u16) -> SocketAddr {
    match ip {
        IpAddr::V4(ip) => SocketAddr::from((ip, port)),
        IpAddr::V6(ip) => SocketAddr::from((ip, port)),
    }
}

/// Axons are QUIC backbone links that connect Aciedo's global infrastructure
/// together.
struct Axon {
    conn: quinn::Connection,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl Axon {
    /// Creates an axon using an in-progress connection.
    async fn new(in_progress: Connecting) -> Result<Self, ConnectingError> {
        let remote_addr = in_progress.remote_address();
        let local_ip = in_progress.local_ip().expect("local IP address missing");
        let axon = Axon { 
            conn: in_progress.await?,
            local_addr: ip_addr_to_socket_addr(local_ip, NEURON_PORT),
            remote_addr,
        };
        axon.setup_heart().await?;
        Ok(axon)
    }

    fn id(&self) -> usize {
        self.conn.stable_id()
    }
    
    async fn setup_heart(&self) -> Result<(), ConnectingError> {
        // heartbeats aren't very useful 
        let (mut hb_send, hb_receive) = self.conn.open_bi().await?;
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(10));
            loop {
                interval.tick().await;
                hb_send.write(&[1]).await.unwrap();
            }
        });
        Ok(())
    }
}


struct AxonController {}

struct PartitionStreamController {}

struct AxonPartitionController {}
