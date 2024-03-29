use std::io;

use quinn::{ReadExactError, ReadToEndError, WriteError};
use quinn_proto::{ConnectError, ConnectionError};

use super::wire::MessageType;

#[derive(Debug)]
pub enum Error {
    ConnectError(ConnectError),
    ConnectionError(ConnectionError),
    Io(io::Error),
    WriteError(WriteError),
    ReadExactError(ReadExactError),
    ReadToEndError(ReadToEndError),
    ReceivedUnexpectedMessageType {
        wanted: MessageType,
        got: MessageType,
    },
    PeerSignatureDidNotMatchChallengeGiven,
    PeerCertNotSignedByCA,
    PeerCertDoesNotIncludeTheirAddr,
    PeerCertIDDoesNotMatchPublicKey,
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
