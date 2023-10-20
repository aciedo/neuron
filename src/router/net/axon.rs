use std::{net::SocketAddr, sync::Arc, time::Duration};

use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use chrono::Utc;
use kt2::{Signature, SIGN_BYTES};
use quinn::{Connecting, RecvStream, SendStream};
use rkyv::{
    de::deserializers::SharedDeserializeMap,
    from_bytes,
    ser::serializers::{
        AlignedSerializer, AllocScratch, CompositeSerializer, FallbackScratch,
        HeapScratch, SharedSerializeMap,
    },
    to_bytes,
    validation::validators::DefaultValidator,
    AlignedVec, Archive, Deserialize, Serialize,
};
use tracing::{debug, debug_span, Instrument};
use zstd::{decode_all as decompress, encode_all as compress};

use super::{
    error::Error::{self, *},
    ski::{Challenge, RouterIdentityService, ServiceIdentity},
    wire::{InnerMessageBuf, MessagePrefix, MessageType, SignedControlMessage},
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
                    hs_send_stream
                        .send(
                            MessageType::AChallengeForYou,
                            &challenge_for_peer,
                        )
                        .await?;
                    debug!("sent challenge to peer");

                    let (peer_identity, sig, challenge_for_me): (
                        ServiceIdentity,
                        Signature,
                        Challenge,
                    ) = hs_recv_stream
                        .receive(MessageType::MyIdentityAndAChallengeForYou)
                        .await?;

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

                    hs_send_stream
                        .send(MessageType::MyIdentity, &(our_cert, our_sig))
                        .await?;
                    debug!("sent our certificate to peer");

                    hs_recv_stream.receive(MessageType::Ready).await?;
                    debug!("handshake complete");
                    (
                        ControlSendStream::new(
                            hs_send_stream,
                            id_service.clone(),
                        ),
                        ControlRecvStream::new(hs_recv_stream),
                        peer_identity,
                    )
                } else {
                    // we're on the receiving end of the connection
                    debug!("waiting for peer to open handshake stream");
                    let (raw_tx, raw_rx) = conn.accept_bi().await?;
                    let mut hs_send_stream = HandshakeSendStream::new(raw_tx);
                    let mut hs_recv_stream = HandshakeRecvStream::new(raw_rx);
                    debug!("peer opened handshake stream");

                    // First, we expect to receive a challenge from the
                    // initiator
                    let challenge_for_me = hs_recv_stream
                        .receive(MessageType::AChallengeForYou)
                        .await?;
                    debug!("received challenge from peer");

                    // Then, we sign the challenge and send back our
                    // certificate.
                    let our_cert = (*id_service.identity()).clone();
                    let our_sig = id_service.sign_challenge(challenge_for_me);
                    let challenge_for_peer = Challenge::new();
                    hs_send_stream
                        .send(
                            MessageType::MyIdentityAndAChallengeForYou,
                            &(our_cert, our_sig, challenge_for_peer.clone()),
                        )
                        .await?;
                    debug!("sent our certificate to peer");

                    // Finally, we expect to receive a certificate from the
                    // initiator, and validate it
                    let (peer_identity, peer_sig) =
                        hs_recv_stream.receive(MessageType::MyIdentity).await?;

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

                    hs_send_stream.send(MessageType::Ready, &()).await?;
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

    pub async fn send<T>(
        &mut self,
        msg_type: MessageType,
        msg: &T,
    ) -> Result<(), Error>
    where
        T: Archive
            + Serialize<
                CompositeSerializer<
                    AlignedSerializer<AlignedVec>,
                    FallbackScratch<HeapScratch<512>, AllocScratch>,
                    SharedSerializeMap,
                >,
            >,
    {
        let msg = to_bytes(msg).unwrap();
        let msg =
            tokio::task::spawn_blocking(move || compress(msg.as_slice(), 0))
                .await
                .unwrap()?;
        let prefix = MessagePrefix::new(false, false, msg_type);
        let len = msg.len();
        let mut buf = Vec::with_capacity(1 + 4 + len);
        buf.push(prefix.into());
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

    pub async fn receive<T>(
        &mut self,
        desired_message_type: MessageType,
    ) -> Result<T, Error>
    where
        T: Archive,
        <T as Archive>::Archived: for<'a> rkyv::CheckBytes<DefaultValidator<'a>>
            + Deserialize<T, SharedDeserializeMap>,
    {
        let mut prefix_buf = [0u8; 5];
        self.0.read_exact(&mut prefix_buf).await?;
        let prefix = MessagePrefix::try_from(prefix_buf[0]).unwrap();
        let len = LittleEndian::read_u32(&prefix_buf[1..]);
        let mut msg_buf = vec![0u8; len as usize];
        self.0.read_exact(&mut msg_buf).await?;
        let msg = decompress(msg_buf.as_slice())?;
        let msg_type = prefix.msg_type();
        if msg_type != desired_message_type {
            Err(ReceivedUnexpectedMessageType {
                wanted: desired_message_type,
                got: msg_type,
            })?
        }
        Ok(from_bytes(&msg).unwrap())
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

    pub async fn send<T>(
        &mut self,
        msg_type: MessageType,
        msg: &T,
    ) -> Result<(), Error>
    where
        T: Archive
            + Serialize<
                CompositeSerializer<
                    AlignedSerializer<AlignedVec>,
                    FallbackScratch<HeapScratch<512>, AllocScratch>,
                    SharedSerializeMap,
                >,
            >,
    {
        let mut msg = compress(to_bytes(msg).unwrap().as_ref(), 0)?;
        let prefix = MessagePrefix::new(false, false, msg_type);
        let mut buf = Vec::with_capacity(1 + 8 + 4 + msg.len() + SIGN_BYTES);
        buf.push(prefix.into()); // 1 byte
        buf.extend_from_slice(&Utc::now().timestamp_micros().to_le_bytes()); // 8 bytes
        buf.extend_from_slice(&(msg.len() as u32).to_le_bytes()); // 4 bytes
        buf.append(&mut msg);
        buf.extend_from_slice(&self.id_service.sign(&buf[1..]).0); // SIGN_BYTES
        self.stream.write_all(&buf).await?;
        Ok(())
    }

    pub async fn send_scm(
        &mut self,
        scm: SignedControlMessage,
    ) -> Result<(), Error> {
        self.stream.write_all(&scm.encode()).await?;
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
        // read the msg prefix, sent_at, and len
        let mut prefix_buf = [0u8; 1 + 8 + 4];
        self.stream.read(&mut prefix_buf).await.unwrap();

        let prefix = MessagePrefix::from(prefix_buf[0]);
        let msg_len = LittleEndian::read_u32(&prefix_buf[9..]);

        let mut len_to_read = msg_len
            .checked_add(SIGN_BYTES as u32)
            .ok_or(MessageLengthOverflowed)?
            as usize;

        if prefix.has_origin() {
            len_to_read =
                len_to_read.checked_add(4).ok_or(MessageLengthOverflowed)?
                    as usize;
        }

        if prefix.has_destination() {
            len_to_read =
                len_to_read.checked_add(4).ok_or(MessageLengthOverflowed)?
                    as usize;
        }

        let mut buf = vec![0u8; 8 + 4 + len_to_read];
        buf[0..12].copy_from_slice(&prefix_buf[1..]);
        self.stream.read_exact(&mut buf[12..]).await?;

        let sig_and_maybe_sid = buf.split_off(8 + 4 + msg_len as usize);
        let sig = Signature(*array_ref![sig_and_maybe_sid, 0, SIGN_BYTES]);

        if prefix.has_origin() {
            let forwarded_from_origin =
                array_ref![sig_and_maybe_sid, SIGN_BYTES, 4];
            if prefix.has_destination() {
                // message was forwarded, and needs to be forwarded again
                let destination =
                    array_ref![sig_and_maybe_sid, SIGN_BYTES + 4, 4];
                return Ok(SignedControlMessage {
                    buf: InnerMessageBuf(buf),
                    sig,
                    origin: Some(*forwarded_from_origin),
                    destination: Some(*destination),
                    msg_type: prefix.msg_type(),
                });
            } else {
                // message was forwarded to us
                return Ok(SignedControlMessage {
                    buf: InnerMessageBuf(buf),
                    sig,
                    origin: Some(*forwarded_from_origin),
                    destination: None,
                    msg_type: prefix.msg_type(),
                });
            }
        } else if prefix.has_destination() {
            let destination = array_ref![sig_and_maybe_sid, SIGN_BYTES, 4];
            // message was sent directly to us and needs to be forwarded
            return Ok(SignedControlMessage {
                buf: InnerMessageBuf(buf),
                sig,
                origin: None,
                destination: Some(*destination),
                msg_type: prefix.msg_type(),
            });
        } else {
            // message was sent directly to us
            return Ok(SignedControlMessage {
                buf: InnerMessageBuf(buf),
                sig,
                origin: None,
                destination: None,
                msg_type: prefix.msg_type(),
            });
        }
    }
}
