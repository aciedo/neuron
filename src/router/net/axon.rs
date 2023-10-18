use crate::router::net::wire::ControlMessage;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use chrono::Utc;
use kt2::{Signature, SIGN_BYTES};
use quinn::{Connecting, RecvStream, SendStream};
use tracing::{debug, debug_span, Instrument};

use super::{
    error::Error::{self, *},
    ski::{Challenge, RouterIdentityService, ServiceID, ServiceIdentity},
    wire::{
        HandshakeMessage::{self, *},
        InnerMessageBuf, SignedControlMessage,
    },
};

/// Axons are QUIC backbone links that connect Aciedo's global infrastructure
/// together.
///
/// Can be cloned to obtain another handle to the same axon.
#[derive(Clone)]
pub struct Axon {
    conn: quinn::Connection,
    remote_addr: SocketAddr,
}

impl Axon {
    /// Creates an axon using an in-progress connection. This completes the
    /// handshake and returns itself and the axon's control streams.
    pub async fn new(
        in_progress: Connecting,
        should_open_streams: bool,
        id_service: Arc<RouterIdentityService>,
    ) -> Result<
        (Self, ControlSendStream, ControlRecvStream, ServiceIdentity),
        Error,
    > {
        let remote_addr = in_progress.remote_address();
        let span = debug_span!("axon", remote = %remote_addr);
        async move {
            debug!("establishing QUIC connection");
            let conn = in_progress.await?;
            debug!("connected via QUIC");
            let (send_stream, recv_stream, peer_identity) =
                if should_open_streams {
                    debug!("opening handshake stream");
                    // wait a few milliseconds
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    // we're the initiator of the handler
                    debug!("opening control stream");
                    let (raw_tx, raw_rx) = conn.open_bi().await?;
                    raw_tx.set_priority(1).unwrap();
                    let mut hs_send_stream = HandshakeSendStream::new(raw_tx);
                    let mut hs_recv_stream = HandshakeRecvStream::new(raw_rx);
                    let challenge_for_peer = Challenge::new();
                    let msg = AChallengeForYou(challenge_for_peer.clone());
                    hs_send_stream.send(msg).await?;
                    debug!("sent challenge to peer");

                    let (peer_identity, sig, challenge_for_me) =
                        match hs_recv_stream.receive().await? {
                            MyIdentityAndAChallengeForYou(x) => x,
                            other => Err(ReceivedBadHandshakeMessage(other))?,
                        };

                    debug!("received peer's certificate");

                    if !peer_identity.cert.validate_self_id() {
                        Err(PeerCertIDDoesNotMatchPublicKey)?
                    }

                    if !id_service.validate_identity_against_ca(&peer_identity)
                    {
                        Err(PeerCertNotSignedByCA)?
                    }

                    if !peer_identity
                        .cert
                        .validate_challenge(challenge_for_peer, sig)
                    {
                        Err(PeerSignatureDidNotMatchChallengeGiven)?
                    }

                    if !peer_identity.cert.includes_socket_addr(&remote_addr) {
                        Err(PeerCertDoesNotIncludeTheirAddr)?
                    }

                    debug!("peer's certificate is valid");

                    let our_sig = id_service.sign_challenge(challenge_for_me);
                    let our_cert = (*id_service.identity()).clone();
                    let msg = MyIdentity((our_cert, our_sig));
                    hs_send_stream.send(msg).await?;
                    debug!("sent our certificate to peer");

                    match hs_recv_stream.receive().await? {
                        Ready => {
                            debug!("handshake complete");
                            (
                                ControlSendStream::new(
                                    hs_send_stream,
                                    id_service.clone(),
                                ),
                                ControlRecvStream::new(hs_recv_stream),
                                peer_identity,
                            )
                        }
                        other => Err(ReceivedBadHandshakeMessage(other))?,
                    }
                } else {
                    // we're on the receiving end of the connection
                    debug!("waiting for peer to open handshake stream");
                    let (raw_tx, raw_rx) = conn.accept_bi().await?;
                    let mut hs_send_stream = HandshakeSendStream::new(raw_tx);
                    let mut hs_recv_stream = HandshakeRecvStream::new(raw_rx);
                    debug!("peer opened handshake stream");

                    // First, we expect to receive a challenge from the
                    // initiator
                    let challenge_for_me =
                        match hs_recv_stream.receive().await? {
                            AChallengeForYou(challenge) => challenge,
                            other => Err(ReceivedBadHandshakeMessage(other))?,
                        };
                    debug!("received challenge from peer");

                    // Then, we sign the challenge and send back our
                    // certificate.
                    let our_cert = (*id_service.identity()).clone();
                    let our_sig =
                        id_service.sign_challenge(challenge_for_me.clone());
                    let challenge_for_peer = Challenge::new();
                    let msg = MyIdentityAndAChallengeForYou((
                        our_cert,
                        our_sig,
                        challenge_for_peer.clone(),
                    ));
                    hs_send_stream.send(msg).await?;
                    debug!("sent our certificate to peer");

                    // Finally, we expect to receive a certificate from the
                    // initiator, and validate it
                    let (peer_identity, peer_sig) =
                        match hs_recv_stream.receive().await? {
                            MyIdentity((cert, sig)) => (cert, sig),
                            other => Err(ReceivedBadHandshakeMessage(other))?,
                        };

                    if !id_service.validate_identity_against_ca(&peer_identity)
                    {
                        Err(PeerCertNotSignedByCA)?
                    }

                    if !peer_identity
                        .cert
                        .validate_challenge(challenge_for_peer, peer_sig)
                    {
                        Err(PeerSignatureDidNotMatchChallengeGiven)?
                    }

                    if !peer_identity.cert.includes_socket_addr(&remote_addr) {
                        Err(PeerCertDoesNotIncludeTheirAddr)?
                    }

                    debug!("peer's certificate is valid");

                    hs_send_stream.send(Ready).await?;
                    debug!("handshake complete");

                    (
                        ControlSendStream::new(
                            hs_send_stream,
                            id_service.clone(),
                        ),
                        ControlRecvStream::new(hs_recv_stream),
                        peer_identity,
                    )
                };

            Ok((
                Axon { conn, remote_addr },
                send_stream,
                recv_stream,
                peer_identity,
            ))
        }
        .instrument(span)
        .await
    }

    pub fn id(&self) -> usize {
        self.conn.stable_id()
    }

    pub fn conn(&self) -> &quinn::Connection {
        &self.conn
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

pub struct HandshakeSendStream(SendStream);

impl HandshakeSendStream {
    pub fn new(stream: SendStream) -> Self {
        Self(stream)
    }

    pub async fn send(&mut self, msg: HandshakeMessage) -> Result<(), Error> {
        let msg = msg.encode().unwrap();
        let len = msg.len();
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&(len as u32).to_le_bytes());
        buf.extend_from_slice(&msg);
        self.0.write_all(&buf).await?;
        Ok(())
    }
}

pub struct HandshakeRecvStream(RecvStream);

impl HandshakeRecvStream {
    pub fn new(stream: RecvStream) -> Self {
        Self(stream)
    }

    pub async fn receive(&mut self) -> Result<HandshakeMessage, Error> {
        let mut len_buf = [0u8; 4];
        self.0.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf);
        let mut msg_buf = vec![0u8; len as usize];
        self.0.read_exact(&mut msg_buf).await?;
        let msg = HandshakeMessage::decode(&msg_buf).unwrap();
        Ok(msg)
    }
}

pub struct ControlSendStream {
    stream: SendStream,
    id_service: Arc<RouterIdentityService>,
}

impl ControlSendStream {
    pub fn new(
        stream: HandshakeSendStream,
        id_service: Arc<RouterIdentityService>,
    ) -> Self {
        Self {
            stream: stream.0,
            id_service,
        }
    }

    pub async fn send(
        &mut self,
        msg: ControlMessage,
        forwarded_from: Option<ServiceID>,
    ) -> Result<(), Error> {
        let msg = msg.encode().unwrap();
        let len = msg.len();
        let sent_at = Utc::now().timestamp_micros();
        let capacity = 1
            + 8
            + 4
            + len
            + SIGN_BYTES
            + if forwarded_from.is_some() { 32 } else { 0 };
        let mut buf = Vec::with_capacity(capacity);
        buf.push(forwarded_from.is_some() as u8); // 1 byte
        buf.extend_from_slice(&sent_at.to_le_bytes()); // 8 bytes
        buf.extend_from_slice(&(len as u32).to_le_bytes()); // 4 bytes
        buf.extend_from_slice(&msg); // len bytes
        buf.extend_from_slice(&self.id_service.sign(&buf[1..]).0); // SIGN_BYTES bytes
        self.stream.write_all(&buf).await?;
        Ok(())
    }
}

pub struct ControlRecvStream {
    stream: RecvStream,
}

impl ControlRecvStream {
    pub fn new(stream: HandshakeRecvStream) -> Self {
        Self { stream: stream.0 }
    }

    pub async fn recv(&mut self) -> Result<SignedControlMessage, Error> {
        // forwarded message:
        // FORWARD_FLAG | sent_at | len | msg | sig | service_id
        // non-forwarded message:
        // FORWARD_FLAG | sent_at | len | msg | sig

        // read the forward flag, sent_at, and len
        let mut prefix_buf = [0u8; 1 + 8 + 4];
        self.stream.read(&mut prefix_buf).await.unwrap();

        let forwarded_message = prefix_buf[0] == 1;
        let msg_len = LittleEndian::read_u32(&prefix_buf[9..]);

        let len_to_read = if forwarded_message {
            msg_len
                .checked_add(SIGN_BYTES as u32 + 32)
                .ok_or(MessageLengthOverflowed)? as usize
        } else {
            msg_len
                .checked_add(SIGN_BYTES as u32)
                .ok_or(MessageLengthOverflowed)? as usize
        };

        let mut buf = vec![0u8; 8 + 4 + len_to_read];
        buf[0..12].copy_from_slice(&prefix_buf[1..]);
        self.stream.read_exact(&mut buf[12..]).await?;

        let sig_and_maybe_sid = buf.split_off(8 + 4 + msg_len as usize);
        let sig = Signature(*array_ref![sig_and_maybe_sid, 0, SIGN_BYTES]);
        let service_id = if forwarded_message {
            Some(*array_ref![sig_and_maybe_sid, SIGN_BYTES, 32])
        } else {
            None
        };

        Ok(SignedControlMessage {
            buf: InnerMessageBuf(buf),
            signature: sig,
            forwarded_from: service_id,
        })
    }
}
