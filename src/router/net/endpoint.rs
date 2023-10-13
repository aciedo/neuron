use std::{
    io::{self, BufReader, Cursor},
    net::{IpAddr, SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use hashbrown::HashMap;
use petgraph::prelude::DiGraphMap;
use quinn::{default_runtime, WriteError};
use rustls::{
    internal::msgs::codec::Codec, server::AllowAnyAuthenticatedClient,
    Certificate as RustlsCert, PrivateKey,
};
use tokio::{
    select,
    sync::{mpsc, RwLock},
};
use tracing::{debug, warn};

use crate::router::net::{
    ski::HexDisplayExt,
    wire::{
        ControlMessage::{self, *},
        SignedControlMessage,
    },
};

use super::{
    axon::{Axon, ControlRecvStream, ControlSendStream},
    error::Error,
    ip_addr_to_socket_addr,
    ski::{Certificate, RouterIdentityService, ServiceID, ServiceIdentity},
    NEURON_PORT, SKI_ROOT_CA,
};

struct Node {}

type NetworkGraph = DiGraphMap<ServiceID, u128>;

struct Endpoint {
    ep: Arc<quinn::Endpoint>,
    routers: Arc<RwLock<HashMap<ServiceID, Certificate>>>,
    axons: Arc<RwLock<HashMap<usize, Axon>>>,
    network_graph: Arc<RwLock<NetworkGraph>>,
    new_control_streams_tx: mpsc::UnboundedSender<(
        ControlSendStream,
        ControlRecvStream,
        ServiceIdentity,
    )>,
    id_service: Arc<RouterIdentityService>,
}

impl Endpoint {
    /// Creates a new QUIC endpoint bound to the given socket address with the
    /// given TLS configuration.
    pub fn new(
        // An IP address to bind to.
        ip_addr: IpAddr,
        tls_key: &[u8],
        tls_cert: &[u8],
        // Handles SKI's additional security layer on top of TLS
        id_service: Arc<RouterIdentityService>,
    ) -> io::Result<Self> {
        let socket =
            UdpSocket::bind(ip_addr_to_socket_addr(ip_addr, NEURON_PORT))?;
        let runtime = default_runtime().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no async runtime found")
        })?;

        let (client_tls, server_tls) =
            Self::tls_config(tls_cert, tls_key).unwrap();

        // shared transport configuration for the server and client sides
        // this is the default config with the BBR congestion controller enabled
        let mut transport_config = quinn::TransportConfig::default();
        let bbr_config = quinn::congestion::BbrConfig::default();
        transport_config.congestion_controller_factory(Arc::new(bbr_config));
        transport_config.keep_alive_interval(Some(Duration::from_millis(25)));
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

        let network_graph = Arc::new(RwLock::new(NetworkGraph::new()));
        let routers = Arc::new(RwLock::new(HashMap::new()));
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
        tokio::spawn(Self::start_netwatch(
            network_graph.clone(),
            routers.clone(),
            new_control_streams_rx,
        ));
        Ok(Self {
            ep,
            routers,
            axons,
            network_graph,
            new_control_streams_tx,
            id_service,
        })
    }

    /// Accepts incoming axons and spawns tasks to handle them.
    /// This will run until the endpoint is shut down, so it should be spawned
    /// in a dedicated task.
    async fn start_acceptor(
        axons: Arc<RwLock<HashMap<usize, Axon>>>,
        new_control_streams_tx: mpsc::UnboundedSender<(
            ControlSendStream,
            ControlRecvStream,
            ServiceIdentity,
        )>,
        id_service: Arc<RouterIdentityService>,
        ep: Arc<quinn::Endpoint>,
    ) {
        while let Some(in_progress) = ep.accept().await {
            let axons = axons.clone();
            let new_control_streams_tx = new_control_streams_tx.clone();
            let id_service = id_service.clone();
            tokio::spawn(async move {
                if let Ok((axon, send_stream, recv_stream, cert)) =
                    Axon::new(in_progress, false, id_service).await
                {
                    axons.write().await.insert(axon.id(), axon);
                    new_control_streams_tx
                        .send((send_stream, recv_stream, cert))
                        .expect("netwatch isn't running");
                }
            });
        }
    }

    /// Handles control traffic and updating the network graph.
    async fn start_netwatch(
        graph: Arc<RwLock<NetworkGraph>>,
        routers: Arc<RwLock<HashMap<ServiceID, Certificate>>>,
        mut new_control_channels_rx: mpsc::UnboundedReceiver<(
            ControlSendStream,
            ControlRecvStream,
            ServiceIdentity,
        )>,
    ) {
        let (new_msg_tx, mut new_msg_rx) = mpsc::unbounded_channel();
        let (error_tx, mut error_rx) = mpsc::unbounded_channel();
        let mut stream_senders = HashMap::new();
        let mut identities = HashMap::new();
        loop {
            select! {
                Some((send_stream, mut recv_stream, identity)) = new_control_channels_rx.recv() => {
                    let error_tx = error_tx.clone();
                    let new_msg_tx = new_msg_tx.clone();
                    let id = identity.cert.id.clone();
                    identities.insert(identity.cert.id.clone(), identity);
                    stream_senders.insert(id, send_stream);
                    tokio::spawn(async move {
                        loop {
                            match recv_stream.recv().await {
                                Ok(msg) => { let _ = new_msg_tx.send((msg, id)); },
                                Err(Error::WriteError(e)) => {
                                    match e {
                                        WriteError::Stopped(_) => todo!(),
                                        WriteError::ConnectionLost(_) => todo!(),
                                        WriteError::UnknownStream => todo!(),
                                        WriteError::ZeroRttRejected => todo!(),
                                    }
                                }
                                Err(e) => { let _ = error_tx.send(e); },
                            };
                        }
                    });
                }
                Some((new_msg, id)) = new_msg_rx.recv() => {
                    let SignedControlMessage {
                        msg,
                        sent_at,
                        signature,
                        forwarded_from
                    } = new_msg;
                    // verify message's signature to verify who sent it
                    // todo: we should be able to do this without reassembly into another vec
                    let mut buf = Vec::with_capacity(8 + 4 + msg.len());
                    buf.extend_from_slice(&sent_at.to_be_bytes());
                    buf.extend_from_slice(&(msg.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&msg);
                    let origin = match forwarded_from {
                        Some(originator) => originator,
                        None => id.clone(),
                    };
                    if !match identities.get(&origin) {
                        Some(identity) => identity.cert.public_key.verify(&buf, &signature),
                        None => {
                            warn!("Received a message from unknown origin through peer {}. Ignoring.",
                                id.hex());
                            continue;
                        },
                    } {
                        warn!("Received bad signature for a message from peer {} through peer {}. Ignoring.",
                            origin.hex(), id.hex());
                        continue;
                    }
                    // the incoming message is valid, so we can process it
                    let msg = match ControlMessage::decode(&msg) {
                        Some(msg) => msg,
                        None => {
                            warn!("Received a message from peer {} that could not be decoded. Ignoring.",
                                id.hex());
                            continue;
                        },
                    };
                    match msg {
                        ControlMessage::NewRouter(identity) => todo!(),
                        ControlMessage::DeadRouter(id) => todo!(),
                        ControlMessage::RTT(target, lat) => {
                            if let Some(old_rtt) = graph.write().await.add_edge(id, target, lat) {
                                debug!("Updated RTT from peer {} to peer {} from {}ms to {}ms",
                                    id.hex(), target.hex(), old_rtt as f32 / 1000.0, lat as f32 / 1000.0);
                            } else {
                                debug!("Added RTT of {}ms from peer {} to peer {} ",
                                    lat as f32 / 1000.0, id.hex(), target.hex());
                            }
                        },
                        ControlMessage::WhoIs(id) => {
                            // if we have a router with this id, send its identity to the origin
                            if let Some(identity) = identities.get(&id) {
                                let msg = ServiceIDMatched(identity.clone());
                                // if let Some()
                                // let _ = stream_senders.get_mut(&id).unwrap().send(msg).await;
                            } // else, forward the message to all peers except the origin and the peer that sent it
                            else {

                            }
                        },
                        ControlMessage::ServiceIDMatched(_) => todo!(),
                    }
                }
                Some(error) = error_rx.recv() => {

                }
            }
        }
    }

    pub async fn connect(
        &self,
        remote: SocketAddr,
        remote_name: &str,
    ) -> Result<(), Error> {
        let (axon, send_stream, recv_stream, service_identity) = Axon::new(
            self.ep.connect(remote, remote_name)?,
            true,
            self.id_service.clone(),
        )
        .await?;
        self.axons.write().await.insert(axon.id(), axon);
        self.new_control_streams_tx
            .send((send_stream, recv_stream, service_identity))
            .expect("netwatch isn't running");
        Ok(())
    }

    /// Returns rustls configurations using SKI's root CA.
    /// Both client and server validate each other using the root CA.
    fn tls_config(
        cert: &[u8],
        key: &[u8],
    ) -> Result<(rustls::ClientConfig, rustls::ServerConfig), rustls::Error>
    {
        let root_ca = RustlsCert::read_bytes(SKI_ROOT_CA)?;
        let mut root_certs = rustls::RootCertStore::empty();
        root_certs.add(&root_ca)?;

        let cert = RustlsCert::read_bytes(cert)?;
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
                // RustlsCert against the root CA, including host name, role
                // checks etc ensure that the client is an
                // actual neuron router
                AllowAnyAuthenticatedClient::new(root_certs).boxed(),
            )
            .with_single_cert(vec![cert], PrivateKey(key))?;

        Ok((client_config, server_config))
    }
}
