use kt2::Signature;

use super::ski::ServiceID;

/// Message prefix is 8 bits. The first bit specifies whether the message is
/// forwarded or not. The second bit specifies whether the message needs to be
/// forwarded or not. The last 6 bits specify the message type.
///
/// - `needs_forwarding && forwarded` => forwarded message received from a peer,
///   needs to be forwarded to the next hop
/// - `needs_forwarding && !forwarded` => one of our peers needs us to forward
///   this message to the next hop
/// - `!needs_forwarding && forwarded` => message received from a peer, this is
///   a message meant for us that has been echoed
/// - `!needs_forwarding && !forwarded` => message received from a peer meant
///   for us
pub struct MessagePrefix(u8);

impl MessagePrefix {
    pub fn new(
        forwarded: bool,
        needs_forwarding: bool,
        msg_type: MessageType,
    ) -> Self {
        let mut prefix = 0b0000_0000;
        if forwarded {
            prefix |= 0b1000_0000;
        }
        if needs_forwarding {
            prefix |= 0b0100_0000;
        }
        prefix |= msg_type as u8;
        Self(prefix)
    }

    pub fn forwarded(&self) -> bool {
        self.0 & 0b1000_0000 != 0
    }

    pub fn needs_forwarding(&self) -> bool {
        self.0 & 0b0100_0000 != 0
    }

    pub fn msg_type(&self) -> MessageType {
        MessageType::try_from(self.0 & 0b0011_1111).unwrap()
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
#[derive(Clone)]
pub struct InnerMessageBuf(pub Vec<u8>);

/// A partially deconstructed wire message
#[derive(Clone)]
pub struct SignedControlMessage {
    /// The type of message
    pub msg_type: MessageType,
    /// sent_at | len | msg
    pub buf: InnerMessageBuf,
    /// the signature of sent_at | msg.len() | msg
    pub sig: Signature,
    /// if `msg_prefix.forwarded()`, the service ID of the router that
    /// created this message
    pub forwarded_from_origin: Option<ServiceID>,
    /// if `msg_prefix.needs_forwarding()`, the service ID of the router that
    /// should receive this message
    pub destination: Option<ServiceID>,
}
