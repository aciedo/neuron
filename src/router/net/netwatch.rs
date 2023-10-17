use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use byteorder::{ByteOrder, LittleEndian};
use chrono::{NaiveDateTime, TimeZone, Utc};
use hashbrown::{HashMap, HashSet};
use tokio::{
    select,
    sync::{mpsc, RwLock},
};
use tracing::{debug, debug_span, warn};

use crate::router::net::{
    endpoint::LatencyEdge, ski::HexDisplayExt, wire::ControlMessage,
};

use super::{
    axon::ControlSendStream,
    endpoint::{NetworkGraph, NewControlStream},
    error::Error,
    ski::{RouterIdentityService, ServiceID, ServiceIdentity},
    wire::{ControlMessage::*, MessageID, SignedControlMessage},
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
                    Self::send_to_peers(&mut stream_senders, RTT(my_id, rtt.as_micros()), |_| true, Some(my_id), &error_tx).await;
                }
                Some((id, signed_msg)) = new_msg_rx.recv() => {
                    let mut msg_id = [0u8; 8];
                    msg_id[0..4].copy_from_slice(&signed_msg.buf.0[0..4]);
                    msg_id[4..8].copy_from_slice(&signed_msg.buf.0[12..16]);
                    // ignore messages we've already seen in the last 3 minutes
                    if previously_seen_msg_ids.contains(msg_id) {
                        continue;
                    } else {
                        previously_seen_msg_ids.insert(msg_id, Duration::from_secs(180));
                    }

                    // work out who created the message
                    let origin = match signed_msg.forwarded_from {
                        Some(originator) => originator,
                        None => id.clone(),
                    };

                    // ignore messages looped back to us
                    if origin == self.id_service.identity().cert.id {
                        continue;
                    }

                    if let Some(identity) = self.routers.read().await.get(&origin) {
                        if !identity.cert.public_key.verify(&signed_msg.buf.0, &signed_msg.signature) {
                            warn!("Received bad signature for a message from peer {} through peer {}. Ignoring.",
                                origin.hex(), id.hex());
                            continue;
                        }
                    } else {
                        debug!("Received a message from unknown peer {} through peer {}. Querying peers for identity of origin.",
                            origin.hex(), id.hex());
                        queued_messages.entry(origin.clone()).or_insert(Vec::new()).push(signed_msg);
                        if !pending_whois_requests.contains(&origin) {
                            pending_whois_requests.insert(origin.clone());
                            Self::send_to_peers(&mut stream_senders, WhoIs(origin), |peer_id| peer_id != &id, None, &error_tx).await;
                        }
                        continue;
                    }

                    let sent_at = LittleEndian::read_i64(&signed_msg.buf.0[0..8]);
                    let len = LittleEndian::read_u32(&signed_msg.buf.0[8..12]) as usize;

                    let msg = match ControlMessage::decode(&signed_msg.buf.0[12..12+len]) {
                        Some(msg) => msg,
                        None => {
                            warn!("Received a message from peer {} that could not be decoded. Ignoring.",
                                id.hex());
                            continue;
                        },
                    };

                    match msg {
                        ControlMessage::NewRouter(identity) => {
                            if self.routers.read().await.contains_key(&identity.cert.id) {
                                warn!("Received a NewRouter message from peer {} for peer {} that we already know about. Ignoring.",
                                    id.hex(), identity.cert.id.hex());
                                continue;
                            }
                            if !identity.cert.validate_self_id() {
                                warn!("Received a NewRouter message from peer {} for peer {} whose ID didn't match its public key. Ignoring.",
                                    id.hex(), identity.cert.id.hex());
                                continue;
                            }
                            if self.id_service.validate_identity_against_ca(&identity) {
                                warn!("Received a NewRouter message from peer {} for peer {} that wasn't signed by our root CA. Ignoring.",
                                    id.hex(), identity.cert.id.hex());
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

                            debug!("Added new router {} from peer {}", identity.cert.id.hex(), id.hex());
                            Self::send_to_peers(&mut stream_senders, NewRouter(identity), |peer_id| peer_id != &origin, Some(origin), &error_tx).await;
                        },
                        ControlMessage::DeadRouter(id) => {
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
                            Self::send_to_peers(&mut stream_senders, msg, |peer_id| peer_id != &origin, Some(origin), &error_tx).await;
                        },
                        ControlMessage::RTT(target, new_rtt) => {
                            let new_edge = LatencyEdge {
                                rtt: new_rtt,
                                last_updated: Utc.from_utc_datetime(&match NaiveDateTime::from_timestamp_micros(sent_at) {
                                    Some(a) => a,
                                    None => {
                                        warn!("Received an RTT message from peer {} with an invalid timestamp. Ignoring.",
                                            id.hex());
                                        continue;
                                    }
                                })
                            };

                            if let Some(old_edge) = self.graph.write().await.add_edge(id, target, new_edge.clone()) {
                                debug!("Updated RTT from peer {} to peer {} from {}µs to {}µs",
                                    id.hex(), target.hex(), old_edge.rtt, new_edge.rtt);
                            } else {
                                debug!("Added RTT of {}ms from peer {} to peer {}",
                                    new_edge.rtt, id.hex(), target.hex());
                            }
                            Self::send_to_peers(&mut stream_senders, msg, |peer_id| peer_id != &origin, Some(origin), &error_tx).await;
                        },
                        ControlMessage::WhoIs(id) => {
                            // if we have a router with this id, send its identity to the origin
                            if let Some(identity) = self.routers.read().await.get(&id) {
                                let msg = ServiceIDMatched(identity.clone());
                                stream_senders.get_mut(&origin)
                                    .expect("stream sender doesn't exist for a identity in routers")
                                    .send(msg, None).await
                                    .or_else(|e| error_tx.send((id, e)))
                                    .expect("netwatch isn't running");
                            } else {
                                // otherwise, forward the WhoIs message to all peers except the origin
                                Self::send_to_peers(&mut stream_senders, msg, |peer_id| peer_id != &origin, Some(origin), &error_tx).await;
                            }
                        },
                        ControlMessage::ServiceIDMatched(identity) => {
                            if pending_whois_requests.remove(&identity.cert.id) {
                                if !identity.cert.validate_self_id() {
                                    warn!("Received a ServiceIDMatched message from peer {} for peer {} whose ID didn't match its public key. Ignoring.",
                                        id.hex(), identity.cert.id.hex());
                                    continue;
                                }
                                if self.id_service.validate_identity_against_ca(&identity) {
                                    warn!("Received a ServiceIDMatched message from peer {} for peer {} that wasn't signed by our root CA. Ignoring.",
                                        id.hex(), identity.cert.id.hex());
                                    continue;
                                }
                                debug!("Received an identity from peer {} for peer {}",
                                    id.hex(), identity.cert.id.hex());
                                self.routers.write().await.insert(identity.cert.id, identity);
                            }
                        },
                    }
                }
                Some((_peer_id, _error)) = error_rx.recv() => {

                }
            }
        }
    }

    async fn send_to_peers<F>(
        stream_senders: &mut HashMap<ServiceID, ControlSendStream>,
        msg: ControlMessage,
        filter: F,
        forwarded_from: Option<ServiceID>,
        error_tx: &mpsc::UnboundedSender<(ServiceID, Error)>,
    ) where
        F: Fn(&ServiceID) -> bool,
    {
        for (peer_id, sender) in stream_senders.iter_mut() {
            if filter(peer_id) {
                sender
                    .send(msg.clone(), forwarded_from)
                    .await
                    .or_else(|e| error_tx.send((*peer_id, e)))
                    .expect("netwatch isn't running");
            }
        }
    }
}

struct ExpiringSet {
    set: HashSet<MessageID>,
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