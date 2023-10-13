use std::io;

use quinn::{WriteError, ReadToEndError, ReadExactError};
use quinn_proto::{ConnectionError, ConnectError};

use super::wire::{ControlMessage, HandshakeMessage};

pub enum Error {
    ConnectError(ConnectError),
    ConnectionError(ConnectionError),
    Io(io::Error),
    WriteError(WriteError),
    ReadExactError(ReadExactError),
    ReadToEndError(ReadToEndError),
    ReceivedBadHandshakeMessage(HandshakeMessage),
    ReceivedBadControlMessage(ControlMessage),
    PeerSignatureDidNotMatchChallengeGiven,
    PeerCertNotSignedByCA,
    CouldNotDecodeMessage,
    MessageLengthOverflowed,
}

impl From<ConnectError> for Error {
    fn from(error: ConnectError) -> Self {
        Self::ConnectError(error)
    }
}

impl From<ConnectionError> for Error {
    fn from(error: ConnectionError) -> Self {
        Self::ConnectionError(error)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<WriteError> for Error {
    fn from(e: quinn::WriteError) -> Self {
        Self::WriteError(e)
    }
}

impl From<ReadExactError> for Error {
    fn from(e: quinn::ReadExactError) -> Self {
        Self::ReadExactError(e)
    }
}
