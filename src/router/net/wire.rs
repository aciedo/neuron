use kt2::Signature;
use rkyv::{from_bytes, to_bytes, AlignedVec, Archive, Deserialize, Serialize};

use super::ski::{Challenge, ServiceIdentity, ServiceID};

#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub struct SignedControlMessage {
    /// the serialized ControlMessage
    pub msg: Vec<u8>,
    /// A UTC microsecond-precision timestamp of when this message was sent
    pub sent_at: i64,
    /// the signature of sent_at | msg.len() | msg
    pub signature: Signature,
    /// the service ID of the router that created this message
    pub forwarded_from: Option<ServiceID>,
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
/// Messages sent between routers during their Axon handshake
pub enum HandshakeMessage {
    /// A challenge for the peer
    AChallengeForYou(Challenge),
    /// The peer's identity and a challenge for this router
    MyIdentityAndAChallengeForYou((ServiceIdentity, Signature, Challenge)),
    /// This router's identity
    MyIdentity((ServiceIdentity, Signature)),
    /// Handshake complete
    Ready,
}

impl HandshakeMessage {
    pub fn encode(&self) -> Option<AlignedVec> {
        Some(to_bytes::<_, 4096>(self).ok()?)
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        from_bytes(buf).ok()
    }
}

#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
pub enum ControlMessage {
    /// A new router has joined the network
    NewRouter(ServiceIdentity),
    /// A router has been detected as dead
    DeadRouter(ServiceID),
    /// An RTT measurement from a router to another router
    RTT(ServiceID, ServiceID, u128),
    /// A query asking for the identity of a router with a given ID
    WhoIs(ServiceID),
    /// A response to a WhoIs query
    ServiceIDMatches(ServiceIdentity)
}

impl ControlMessage {
    pub fn encode(&self) -> Option<AlignedVec> {
        Some(to_bytes::<_, 4096>(self).ok()?)
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        from_bytes(buf).ok()
    }
}