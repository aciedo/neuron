use crate::router::net::wire::InnerMessageBuf;
use petgraph::algo::astar;
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{NaiveDateTime, TimeZone, Utc};
use hashbrown::{HashMap, HashSet};
use petgraph::{prelude::GraphMap, Directed};
use rkyv::{
    ser::serializers::{
        AlignedSerializer, AllocScratch, CompositeSerializer, FallbackScratch,
        HeapScratch, SharedSerializeMap,
    },
    AlignedVec, Serialize,
};
use tokio::{
    select,
    sync::{mpsc, RwLock},
};
use tracing::{debug, debug_span, trace, warn};

use crate::router::{hex::HexDisplayExt, net::endpoint::LatencyEdge};
use rkyv::from_bytes;

use super::{
    axon::ControlSendStream,
    endpoint::{NetworkGraph, NewControlStream},
    error::Error,
    ski::{RouterIdentityService, ServiceID, ServiceIdentity},
    wire::{MessageID, MessageType, SignedControlMessage},
};

pub struct NetWatch {
    graph: Arc<RwLock<NetworkGraph>>,
    routers: Arc<RwLock<HashMap<ServiceID, ServiceIdentity>>>,
    id_service: Arc<RouterIdentityService>,
}

impl NetWatch {
    pub fn new(id_service: Arc<RouterIdentityService>) -> Self {
        Self {
            graph: Arc::new(RwLock::new(NetworkGraph::new())),
            routers: Arc::new(RwLock::new(HashMap::new())),
            id_service,
        }
    }

    pub async fn start(
        &self,
        mut new_control_channels_rx: mpsc::UnboundedReceiver<NewControlStream>,
    ) {
        let span = debug_span!("netwatch");
        let _guard = span.enter();
        debug!("netwatch started");
        let (new_msg_tx, mut new_msg_rx) = mpsc::unbounded_channel();
        let (rtt_tx, mut rtt_rx) = mpsc::unbounded_channel();
        let (error_tx, mut error_rx) = mpsc::unbounded_channel();
        // stores the sender half for each axon's control stream
        let mut stream_senders = HashMap::new();
        // stores active whois requests we're waiting for responses to
        let mut pending_whois_requests: HashSet<ServiceID> = HashSet::new();
        // stores messages we've received but waiting to process (likely
        // because we're waiting for a whois response for the origin)
        let mut queued_messages: HashMap<ServiceID, Vec<SignedControlMessage>> =
            HashMap::new();

        let mut previously_seen_msg_ids = ExpiringSet::new();
        loop {
            // dequeue any pending messages we can now process
            for id in queued_messages
                .keys()
                .filter(|id| !pending_whois_requests.contains(*id))
                .cloned()
                .collect::<Vec<_>>()
            {
                if let Some(msgs) = queued_messages.remove(&id) {
                    for msg in msgs {
                        new_msg_tx
                            .send((id.clone(), msg))
                            .expect("netwatch isn't running");
                    }
                }
            }

            previously_seen_msg_ids.remove_expired();

            select! {
                Some((axon, send_stream, mut recv_stream, identity)) = new_control_channels_rx.recv() => {
                    debug!("received axon for peer {}", identity.cert.id.hex());
                    let error_tx = error_tx.clone();
                    let new_msg_tx = new_msg_tx.clone();
                    let rtt_tx = rtt_tx.clone();
                    let peer_id = identity.cert.id.clone();
                    self.routers.write().await.insert(identity.cert.id.clone(), identity);
                    stream_senders.insert(peer_id, send_stream);
                    tokio::spawn(async move {
                        let mut rtt_interval = tokio::time::interval(Duration::from_secs(5));

                        loop {
                            select! {
                                msg = recv_stream.recv() => {
                                    match msg {
                                        Ok(msg) => new_msg_tx.send((peer_id, msg)).expect("netwatch isn't running"),
                                        Err(e) => error_tx.send((peer_id, e)).expect("netwatch isn't running"),
                                    };
                                }
                                _ = rtt_interval.tick() => {
                                    debug!("sending axon rtt {:?} for peer {}", axon.conn().rtt(), peer_id.hex());
                                    rtt_tx.send((peer_id, axon.conn().rtt())).expect("netwatch isn't running");
                                }
                            }
                        }
                    });
                }
                Some((peer_id, rtt)) = rtt_rx.recv() => {
                    let my_id = self.id_service.identity().cert.id;
                    self.graph.write().await.add_edge(my_id, peer_id, LatencyEdge {
                        rtt: rtt.as_micros(),
                        last_updated: Utc::now(),
                    });
                    Self::send_to_peers(&mut stream_senders, MessageType::Rtt, &(peer_id, rtt.as_micros()), |_| true, &error_tx).await;
                }
                Some((peer_id, mut scm)) = new_msg_rx.recv() => {
                    let mut msg_id = [0u8; 8];
                    msg_id[0..4].copy_from_slice(&scm.buf.0[0..4]);
                    msg_id[4..8].copy_from_slice(&scm.buf.0[12..16]);
                    // it's often for us to receive the same message multiple times.
                    // this removes any feedback loops when echoing a message around the network
                    if previously_seen_msg_ids.contains(msg_id) {
                        continue;
                    } else {
                        previously_seen_msg_ids.insert(msg_id, Duration::from_secs(300));
                    }

                    // the origin is the peer that created the message
                    // it might be different from the peer that forwarded it to us
                    let origin = match scm.forwarded_from_origin {
                        Some(originator) => originator,
                        None => peer_id.clone(),
                    };

                    // ignore messages looped back to us
                    if origin == self.id_service.identity().cert.id {
                        continue;
                    }

                    if let Some(identity) = self.routers.read().await.get(&origin) {
                        if !identity.cert.public_key.verify(&scm.buf.0, &scm.sig) {
                            if origin == peer_id {
                                warn!("Received bad signature for a message from peer {}. Ignoring.", origin.hex());
                            } else {
                                warn!("Received bad signature for a message from peer {} through peer {}. Ignoring.",
                                    origin.hex(), peer_id.hex());
                            }
                            continue;
                        }
                    } else {
                        queued_messages.entry(origin.clone()).or_insert(Vec::new()).push(scm);
                        pending_whois_requests.insert(origin.clone());
                        debug!("Received a message from unknown peer {} through peer {}. Querying peers for identity of origin.",
                            origin.hex(), peer_id.hex());
                        Self::send_to_peers(&mut stream_senders, MessageType::WhoIs, &origin, |peer_id| peer_id != &origin, &error_tx).await;

                        continue;
                    }

                    // forwarding capabilities are restricted to known peers
                    if let Some(destination) = scm.destination {
                        // just in case the previous hop didn't remove the destination if it was destined for us
                        if destination != self.id_service.identity().cert.id {
                            // don't bother reading the message - it's not for us. we should work out where to send it on its way to the destination
                            let path = astar(&*self.graph.read().await, self.id_service.identity().cert.id, |n| n == destination, |(.., w)| w.rtt, |_| 0);
                            let next_hop = match path {
                                Some((est_lat, path)) => {
                                    debug!("Routing message {} {}..->{}->{}->{}..{} est. remaining latency ~{}µs",
                                        msg_id.hex(), origin.hex(), peer_id.hex(), self.id_service.identity().cert.id.hex(), path[1].hex(), destination.hex(), est_lat);
                                    path[1]
                                },
                                None => {
                                    warn!("No route to destination {} for message {}..->{}->{}..{}",
                                        destination.hex(), origin.hex(), peer_id.hex(), self.id_service.identity().cert.id.hex(), destination.hex());
                                    continue;
                                }
                            };

                            if next_hop == destination {
                                scm.destination = None;
                            }

                            if scm.forwarded_from_origin.is_none() {
                                scm.forwarded_from_origin = Some(origin);
                            }

                            stream_senders
                                .get_mut(&next_hop)
                                .expect("no stream for next hop")
                                .send_scm(scm)
                                .await.expect("netwatch isn't running");
                            continue;
                        }
                    }

                    let (sent_at, msg) = match scm.buf.decode().await {
                        Ok(msg) => msg,
                        Err(e) => {
                            warn!("Received a message from peer {} that could not be deserialized. Ignoring. Error: {:?}",
                                peer_id.hex(), e);
                            continue;
                        }
                    };

                    match scm.msg_type {
                        MessageType::NewRouter => {
                            let identity: ServiceIdentity = match from_bytes(&msg).ok() {
                                Some(identity) => identity,
                                None => {
                                    warn!("Received a NewRouter message from peer {} that could not be deserialized. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            };
                            if self.routers.read().await.contains_key(&identity.cert.id) {
                                warn!("Received a NewRouter message from peer {} for peer {} that we already know about. Ignoring.",
                                    peer_id.hex(), identity.cert.id.hex());
                                continue;
                            }
                            if !identity.cert.validate_self_id() {
                                warn!("Received a NewRouter message from peer {} for peer {} whose ID didn't match its public key. Ignoring.",
                                    peer_id.hex(), identity.cert.id.hex());
                                continue;
                            }
                            if !identity.cert.contains_all_tags(&["neuron-router".into()]) {
                                warn!("Received a NewRouter message from peer {} for peer {} that didn't have the neuron-router tag. Ignoring.",
                                    peer_id.hex(), identity.cert.id.hex());
                                continue;
                            }
                            if self.id_service.validate_identity_against_ca(&identity) {
                                warn!("Received a NewRouter message from peer {} for peer {} that wasn't signed by our root CA. Ignoring.",
                                    peer_id.hex(), identity.cert.id.hex());
                                continue;
                            }

                            let identity1 = identity.clone();
                            let cert_id2 = identity.cert.id.clone();

                            tokio::join!(
                                async {
                                    self.routers.write().await.insert(identity1.cert.id, identity1);
                                },
                                async {
                                    self.graph.write().await.add_node(cert_id2);
                                },
                            );

                            debug!("Added new router {} from peer {}", identity.cert.id.hex(), peer_id.hex());
                            Self::fwd_scm(&mut stream_senders, scm, |id| id != &origin && id != &peer_id, &error_tx).await;
                        },
                        MessageType::DeadRouter => {
                            let id: ServiceID = match from_bytes(&msg).ok() {
                                Some(id) => id,
                                None => {
                                    warn!("Received a DeadRouter message from peer {} that could not be deserialized. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            };
                            tokio::join!(
                                async {
                                    self.routers.write().await.remove(&id);
                                },
                                async {
                                    self.graph.write().await.remove_node(id);
                                },
                            );
                            stream_senders.remove(&id);
                            pending_whois_requests.remove(&id);
                            queued_messages.remove(&id);
                            debug!("Removed dead router {}", id.hex());
                            Self::fwd_scm(&mut stream_senders, scm, |id| id != &origin && id != &peer_id, &error_tx).await;
                        },
                        MessageType::Rtt => {
                            let (target, new_rtt) = match from_bytes(&msg).ok() {
                                Some(o) => o,
                                None => {
                                    warn!("Received an RTT message from peer {} that could not be deserialized. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            };
                            let timestamp = Utc.from_utc_datetime(&match NaiveDateTime::from_timestamp_micros(sent_at) {
                                Some(a) => a,
                                None => {
                                    warn!("Received an RTT message from peer {} with an invalid timestamp. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            });

                            let mut graph = self.graph.write().await;

                            if let Some(edge) = graph.edge_weight(origin, target) {
                                if edge.last_updated > timestamp {
                                    continue;
                                }
                            }

                            let new_edge = LatencyEdge {
                                rtt: new_rtt,
                                last_updated: timestamp
                            };

                            if let Some(old_edge) = graph.add_edge(origin, target, new_edge.clone()) {
                                trace!("Update RTT {} -> {} from {}µs to {}µs",
                                    origin.hex(), target.hex(), old_edge.rtt, new_edge.rtt);
                            } else {
                                trace!("Added RTT {} -> {} of {}µs",
                                     origin.hex(), target.hex(), new_edge.rtt);
                            }
                            drop(graph);
                            trace!("Forwarding RTT message {} from {} to other peers",
                               msg_id.hex(), origin.hex());

                            if scm.forwarded_from_origin.is_none() {
                                scm.forwarded_from_origin = Some(origin);
                            }

                            Self::fwd_scm(&mut stream_senders, scm, |id| id != &origin && id != &peer_id, &error_tx).await;
                        },
                        MessageType::WhoIs => {
                            let whois_id: ServiceID = match from_bytes(&msg).ok() {
                                Some(id) => id,
                                None => {
                                    warn!("Received a WhoIs message from peer {} that could not be deserialized. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            };
                            // if we have a router with this id, or we are this id, send it back
                            let mut identity = self.routers.read().await.get(&whois_id).map(|i| i.clone());
                            if identity.is_none() && whois_id == self.id_service.identity().cert.id {
                                identity = Some(self.id_service.identity().clone());
                            }

                            if let Some(ref identity) = identity {
                                if let Some(s) = stream_senders.get_mut(&origin) {
                                    // we have the identity and a direct connection to the origin
                                    s.send(MessageType::ServiceIDMatched, identity).await
                                    .or_else(|e| error_tx.send((whois_id, e)))
                                    .expect("netwatch isn't running");
                                } else {
                                    // we have the identity but no direct connection, so bounce it through our peers
                                    let path = astar(&*self.graph.read().await, self.id_service.identity().cert.id, |n| n == origin, |(.., w)| w.rtt, |_| 0);

                                    let next_hop = match path {
                                        Some((est_lat, path)) => {
                                            trace!("Sending ServiceIDMatched message for {} through {}->{}..{} est. remaining latency ~{}µs",
                                                whois_id.hex(), self.id_service.identity().cert.id.hex(), path[1].hex(), origin.hex(), est_lat);
                                            path[1]
                                        },
                                        None => {
                                            warn!("No route to respond with ServiceIDMatched message for peer {} from peer {}",
                                                whois_id.hex(), origin.hex());
                                            continue;
                                        }
                                    };

                                    let buf = InnerMessageBuf::encode(Utc::now().timestamp_micros(), identity).await;
                                    let scm = SignedControlMessage {
                                        msg_type: MessageType::ServiceIDMatched,
                                        sig: self.id_service.sign(&buf.0),
                                        buf,
                                        forwarded_from_origin: None,
                                        destination: if next_hop == origin { None } else { Some(origin) },
                                    };

                                    stream_senders
                                        .get_mut(&next_hop)
                                        .expect("no stream for next hop")
                                        .send_scm(scm)
                                        .await.expect("netwatch isn't running");
                                    continue;
                                }
                                debug!("Sent identity of peer {} to peer {}", whois_id.hex(), origin.hex());
                            } else {
                                // otherwise, forward the WhoIs message to all peers except the origin and the peer that sent it
                                if scm.forwarded_from_origin.is_none() {
                                    scm.forwarded_from_origin = Some(origin);
                                }
                                Self::fwd_scm(&mut stream_senders, scm, |id| id != &origin && id != &peer_id, &error_tx).await;
                                debug!("Forwarded WhoIs message for peer {} from peer {} to all other peers",
                                    whois_id.hex(), origin.hex());
                            }
                        },
                        MessageType::ServiceIDMatched => {
                            let identity: ServiceIdentity = match from_bytes(&msg).ok() {
                                Some(id) => id,
                                None => {
                                    warn!("Received a ServiceIDMatched message from peer {} that could not be deserialized. Ignoring.",
                                        peer_id.hex());
                                    continue;
                                }
                            };
                            if pending_whois_requests.remove(&identity.cert.id) {
                                if !identity.cert.validate_self_id() {
                                    warn!("Received a ServiceIDMatched message from peer {} for peer {} whose ID didn't match its public key. Ignoring.",
                                        peer_id.hex(), identity.cert.id.hex());
                                    continue;
                                }
                                if !identity.cert.contains_all_tags(&["neuron-router".into()]) {
                                    warn!("Received a ServiceIDMatched message from peer {} for peer {} that didn't have the neuron-router tag. Ignoring.",
                                        peer_id.hex(), identity.cert.id.hex());
                                    continue;
                                }
                                if !self.id_service.validate_identity_against_ca(&identity) {
                                    warn!("Received a ServiceIDMatched message from peer {} for peer {} that wasn't signed by our root CA. Ignoring.",
                                        peer_id.hex(), identity.cert.id.hex());
                                    continue;
                                }
                                debug!("Received an identity from peer {} for peer {}",
                                    peer_id.hex(), identity.cert.id.hex());
                                self.routers.write().await.insert(identity.cert.id, identity);
                            }
                        },
                        _ => continue
                    };
                }
                Some((peer_id, error)) = error_rx.recv() => {
                    panic!("Error from peer {}: {:?}", peer_id.hex(), error);
                }
            }
        }
    }

    /// Sends a message to all peers based on a filter.
    async fn send_to_peers<T, F>(
        stream_senders: &mut HashMap<ServiceID, ControlSendStream>,
        msg_type: MessageType,
        msg: &T,
        filter: F,
        error_tx: &mpsc::UnboundedSender<(ServiceID, Error)>,
    ) where
        F: Fn(&ServiceID) -> bool,
        T: Serialize<
            CompositeSerializer<
                AlignedSerializer<AlignedVec>,
                FallbackScratch<HeapScratch<512>, AllocScratch>,
                SharedSerializeMap,
            >,
        >,
    {
        for (peer_id, sender) in stream_senders.iter_mut() {
            if filter(peer_id) {
                sender
                    .send(msg_type.clone(), msg)
                    .await
                    .or_else(|e| error_tx.send((*peer_id, e)))
                    .expect("netwatch isn't running");
            }
        }
    }

    /// Sends a SCM to all peers based on a filter.
    async fn fwd_scm<F>(
        stream_senders: &mut HashMap<ServiceID, ControlSendStream>,
        scm: SignedControlMessage,
        filter: F,
        error_tx: &mpsc::UnboundedSender<(ServiceID, Error)>,
    ) where
        F: Fn(&ServiceID) -> bool,
    {
        let mut msg_id = [0u8; 8];
        msg_id[0..4].copy_from_slice(&scm.buf.0[0..4]);
        msg_id[4..8].copy_from_slice(&scm.buf.0[12..16]);
        for (peer_id, sender) in stream_senders.iter_mut() {
            if filter(peer_id) {
                sender
                    .send_scm(scm.clone())
                    .await
                    .or_else(|e| error_tx.send((*peer_id, e)))
                    .expect("netwatch isn't running");
            }
        }
    }

    pub fn graph(
        &self,
    ) -> Arc<RwLock<GraphMap<ServiceID, LatencyEdge, Directed>>> {
        self.graph.clone()
    }

    pub fn routers(&self) -> Arc<RwLock<HashMap<ServiceID, ServiceIdentity>>> {
        self.routers.clone()
    }
}

/// An efficient message ID set that expires its entries after a given duration.
struct ExpiringSet {
    /// The set of message IDs used for membership checks.
    set: HashSet<MessageID>,
    /// A priority queue of message IDs and their expiry times.
    queue: BinaryHeap<(Reverse<SystemTime>, MessageID)>,
}

impl ExpiringSet {
    fn new() -> ExpiringSet {
        ExpiringSet {
            set: HashSet::new(),
            queue: BinaryHeap::new(),
        }
    }

    fn insert(&mut self, value: MessageID, ttl: Duration) {
        let expiry = SystemTime::now() + ttl;
        self.set.insert(value);
        self.queue.push((Reverse(expiry), value));
    }

    fn contains(&self, value: MessageID) -> bool {
        self.set.contains(&value)
    }

    fn remove_expired(&mut self) {
        let now = SystemTime::now();
        while self
            .queue
            .peek()
            .map_or(false, |&(expiry, _)| expiry.0 <= now)
        {
            let (_, value) = self.queue.pop().unwrap();
            self.set.remove(&value);
        }
    }
}
