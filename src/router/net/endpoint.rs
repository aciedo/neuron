use std::{
    io::{self, BufReader, Cursor},
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use chrono::{DateTime, Utc};
use hashbrown::HashMap;
use petgraph::prelude::DiGraphMap;
use quinn::default_runtime;
use quinn_proto::{IdleTimeout, VarInt};
use rustls::client::{ServerCertVerified, ServerCertVerifier};

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, debug_span, Instrument};

use crate::router::hex::HexDisplayExt;

use super::{
    axon::{Axon, ControlRecvStream, ControlSendStream},
    error::Error,
    ip_addr_to_socket_addr,
    netwatch::NetWatch,
    ski::{RouterIdentityService, ServiceID, ServiceIdentity},
    NEURON_PORT, SKI_ROOT_CA,
};

#[derive(Clone, Copy)]
pub struct LatencyEdge {
    /// Round-trip-time latency in microseconds
    pub rtt: u128,
    /// Last updated at this time
    pub last_updated: DateTime<Utc>,
}

pub type NetworkGraph = DiGraphMap<ServiceID, LatencyEdge>;

pub type NewControlStream =
    (Axon, ControlSendStream, ControlRecvStream, ServiceIdentity);

pub struct Endpoint {
    ep: Arc<quinn::Endpoint>,
    routers: Arc<RwLock<HashMap<ServiceID, ServiceIdentity>>>,
    axons: Arc<RwLock<HashMap<ServiceID, Axon>>>,
    network_graph: Arc<RwLock<NetworkGraph>>,
    new_control_streams_tx: mpsc::UnboundedSender<NewControlStream>,
    id_service: Arc<RouterIdentityService>,
}

impl Endpoint {
    /// Creates a new QUIC endpoint bound to the given socket address with the
    /// given TLS configuration.
    pub fn new(
        // An IP address to bind to.
        ip_addr: IpAddr,
        // Handles SKI's additional security layer on top of TLS
        id_service: Arc<RouterIdentityService>,
    ) -> io::Result<Self> {
        let socket =
            UdpSocket::bind(ip_addr_to_socket_addr(ip_addr, NEURON_PORT))?;
        let runtime = default_runtime().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no async runtime found")
        })?;

        let (client_tls, server_tls) =
            Self::tls_config(ip_addr.clone()).unwrap();

        // shared transport configuration for the server and client sides
        // this is the default config with the BBR congestion controller enabled
        let mut transport_config = quinn::TransportConfig::default();
        let bbr_config = quinn::congestion::BbrConfig::default();
        transport_config.congestion_controller_factory(Arc::new(bbr_config));
        transport_config.keep_alive_interval(Some(Duration::from_millis(25)));
        transport_config
            // 500ms idle timeout
            .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(500))));
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

        let axons = Arc::new(RwLock::new(HashMap::new()));
        let ep = Arc::new(ep);
        let (new_control_streams_tx, new_control_streams_rx) =
            mpsc::unbounded_channel();
        tokio::spawn(Self::start_acceptor(
            axons.clone(),
            new_control_streams_tx.clone(),
            id_service.clone(),
            ep.clone(),
        ));
        let netwatch = Arc::new(NetWatch::new(id_service.clone()));
        let nw_clone = netwatch.clone();
        tokio::spawn(
            async move { nw_clone.start(new_control_streams_rx).await }
                .instrument(debug_span!(
                    "nw",
                    id = %id_service.identity().cert.id.hex()
                )),
        );
        Ok(Self {
            ep,
            routers: netwatch.routers().clone(),
            axons,
            network_graph: netwatch.graph().clone(),
            new_control_streams_tx,
            id_service,
        })
    }

    /// Accepts incoming axons and spawns tasks to handle them.
    /// This will run until the endpoint is shut down, so it should be spawned
    /// in a dedicated task.
    async fn start_acceptor(
        axons: Arc<RwLock<HashMap<ServiceID, Axon>>>,
        new_control_streams_tx: mpsc::UnboundedSender<NewControlStream>,
        id_service: Arc<RouterIdentityService>,
        ep: Arc<quinn::Endpoint>,
    ) {
        debug!("acceptor started");
        while let Some(in_progress) = ep.accept().await {
            let axons = axons.clone();
            let new_control_streams_tx = new_control_streams_tx.clone();
            let id_service = id_service.clone();
            tokio::spawn(async move {
                if let Ok((axon, send_stream, recv_stream, identity)) =
                    Axon::new(in_progress, false, id_service).await
                {
                    let mut axons = axons.write().await;
                    if axons.contains_key(&identity.cert.id) {
                        debug!(
                            "dropped duplicate axon from {}",
                            identity.cert.id.hex()
                        );
                        return;
                    }
                    debug!("accepted axon from {}", identity.cert.id.hex());
                    axons.insert(identity.cert.id.clone(), axon.clone());
                    new_control_streams_tx
                        .send((axon, send_stream, recv_stream, identity))
                        .expect("netwatch isn't running");
                }
            });
        }
    }

    pub async fn connect(
        &self,
        remote: SocketAddr,
        remote_name: &str,
    ) -> Result<(), Error> {
        let (axon, send_stream, recv_stream, identity) = Axon::new(
            self.ep.connect(remote, remote_name)?,
            true,
            self.id_service.clone(),
        )
        .await?;
        self.axons
            .write()
            .await
            .insert(identity.cert.id, axon.clone());
        self.new_control_streams_tx
            .send((axon, send_stream, recv_stream, identity))
            .expect("netwatch isn't running");
        Ok(())
    }

    /// Returns rustls configurations using SKI's root CA.
    /// Both client and server validate each other using the root CA.
    fn tls_config(
        ip_addr: IpAddr,
    ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), rustls::Error>
    {
        let root_ca = {
            let mut certs = rustls_pemfile::certs(&mut BufReader::new(
                Cursor::new(SKI_ROOT_CA),
            ))
            .unwrap();
            if certs.len() != 1 {
                panic!("expected exactly one certificate");
            }
            rustls::Certificate(certs.remove(0))
        };
        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.add(&root_ca)?;

        let self_signed_cert =
            rcgen::generate_simple_self_signed([ip_addr.to_string()]).unwrap();

        let cert =
            rustls::Certificate(self_signed_cert.serialize_der().unwrap());

        let key =
            rustls::PrivateKey(self_signed_cert.serialize_private_key_der());

        let client_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            // .with_root_certificates(root_certs.clone())
            .with_custom_certificate_verifier(Arc::new(
                NoCertificateVerification {},
            ))
            // .with_client_auth_cert(vec![cert.clone()], key.clone())?;
            .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            // .with_client_cert_verifier(
            //     AllowAnyAuthenticatedClient::new(root_certs).boxed(),
            // )
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        Ok((client_config, server_config))
    }

    pub fn routers(&self) -> Arc<RwLock<HashMap<[u8; 4], ServiceIdentity>>> {
        self.routers.clone()
    }

    pub fn network_graph(&self) -> Arc<RwLock<NetworkGraph>> {
        self.network_graph.clone()
    }
}

pub struct NoCertificateVerification {}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}
