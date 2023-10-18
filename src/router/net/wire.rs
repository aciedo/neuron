use kt2::Signature;
use rkyv::{from_bytes, to_bytes, AlignedVec, Archive, Deserialize, Serialize};

use super::ski::{Challenge, ServiceID, ServiceIdentity};

pub type MessageID = [u8; 8];

/// A buffer containing a sent_at | len | msg concatenation
pub struct InnerMessageBuf(pub Vec<u8>);

/// A partially deconstructed wire message
pub struct SignedControlMessage {
    /// sent_at | len | msg
    pub buf: InnerMessageBuf,
    /// the signature of sent_at | msg.len() | msg
    pub signature: Signature,
    /// the service ID of the router that created this message
    pub forwarded_from: Option<ServiceID>,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct MyIdentityAndAChallengeForYou {
    identity: ServiceIdentity,
    signature: Signature,
    challenge: Challenge,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct MyIdentity {
    identity: ServiceIdentity,
    signature: Signature,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
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
        to_bytes::<_, 4096>(self).ok()
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        from_bytes(buf).ok()
    }
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct NewRouter {
    identity: ServiceIdentity,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct DeadRouter {
    id: ServiceID,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct Rtt {
    id: ServiceID,
    rtt: u128,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct WhoIs {
    id: ServiceID,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
struct ServiceIDMatched {
    identity: ServiceIdentity,
}

#[derive(Archive, Serialize, Deserialize, Clone, Debug)]
#[archive(check_bytes)]
pub enum ControlMessage {
    /// A new router has joined the network
    NewRouter(ServiceIdentity),
    /// A router has been detected as dead
    DeadRouter(ServiceID),
    /// A microsecond precision RTT (round-trip-time) measurement from the
    /// broadcasting to another router
    Rtt(ServiceID, u128),
    /// A query asking for the identity of a router with a given ID.
    /// Sometimes routers will receive messages for peers that they don't know
    /// about
    WhoIs(ServiceID),
    /// A response to a WhoIs query from another router
    ServiceIDMatched(ServiceIdentity),
}

impl ControlMessage {
    pub fn encode(&self) -> Option<AlignedVec> {
        to_bytes::<_, 4096>(self).ok()
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        from_bytes(buf).ok()
    }
}
