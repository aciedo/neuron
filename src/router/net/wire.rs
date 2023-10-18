use kt2::Signature;
use rkyv::{Archive, Deserialize, Serialize};

use super::ski::{Challenge, ServiceID, ServiceIdentity};

/// Message prefix is 8 bits. The first bit specifies whether the message is
/// forwarded or not. The last 7 bits specify the message type.
pub struct MessagePrefix(u8);

impl MessagePrefix {
    pub fn new(forwarded: bool, msg_type: MessageType) -> Self {
        Self((forwarded as u8) << 7 | msg_type as u8)
    }

    pub fn forwarded(&self) -> bool {
        self.0 >> 7 == 1
    }

    pub fn msg_type(&self) -> MessageType {
        MessageType::try_from(self.0 & 0b0111_1111).unwrap()
    }

    pub fn byte(&self) -> u8 {
        self.0
    }
}

impl From<u8> for MessagePrefix {
    fn from(byte: u8) -> Self {
        Self(byte)
    }
}

impl From<MessagePrefix> for u8 {
    fn from(prefix: MessagePrefix) -> Self {
        prefix.0
    }
}

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    // HANDSHAKE MESSAGES
    /// A challenge for the peer
    AChallengeForYou,
    /// The peer's identity and a challenge for this router
    MyIdentityAndAChallengeForYou,
    /// This router's identity
    MyIdentity,
    /// Handshake complete
    Ready,

    // CONTROL MESSAGES
    /// A new router has joined the network
    NewRouter,
    /// A router has been detected as dead
    DeadRouter,
    /// A microsecond precision RTT (round-trip-time) measurement from the
    /// broadcasting to another router
    Rtt,
    /// A query asking for the identity of a router with a given ID.
    /// Sometimes routers will receive messages for peers that they don't know
    /// about
    WhoIs,
    /// A response to a WhoIs query from another router
    ServiceIDMatched,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 0b0111_1111 {
            Err(())
        } else {
            Ok(unsafe { std::mem::transmute(value) })
        }
    }
}

pub type MessageID = [u8; 8];

/// A buffer containing a sent_at | len | compress(msg) concatenation
pub struct InnerMessageBuf(pub Vec<u8>);

/// A partially deconstructed wire message
pub struct SignedControlMessage {
    /// sent_at | len | msg
    pub buf: InnerMessageBuf,
    /// the signature of sent_at | msg.len() | msg
    pub signature: Signature,
    /// the service ID of the router that created this message
    pub forwarded_from: Option<ServiceID>,
    /// The type of message
    pub msg_type: MessageType,
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
