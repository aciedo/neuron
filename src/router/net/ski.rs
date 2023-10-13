// SKI (sharded key infrastructure) is Aciedo's internal quantum-secure PKI
// system. It is custom built for Aciedo's network to allow services to
// authenticate to one another using a standard protocol.
//
// SKI is primarily used alongside KT2 (of which it depends upon) in Aciedo's
// NEURON network in the wire protocol. It's currently hot-wired in a hybrid
// system, which establishes a normal ECC based TLS1.3 connection and then
// authenticates using challenges inside the connection. A custom transit
// encryption protocol using SKI inside KT2 will replace this hybrid system in
// the future.

use hashbrown::{HashMap, HashSet};
use kt2::{PublicKey, SecretKey, Signature};
use rkyv::{to_bytes, Archive, Deserialize, Serialize};
use typed_builder::TypedBuilder;

pub type ServiceID = [u8; 32];

use std::{fmt, net::SocketAddr};

pub struct HexSlice<'a>(&'a [u8]);

impl<'a> HexSlice<'a> {
    fn new<T>(data: &'a T) -> HexSlice<'a>
    where
        T: ?Sized + AsRef<[u8]> + 'a,
    {
        HexSlice(data.as_ref())
    }
}

impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{:X}", byte)?;
        }
        Ok(())
    }
}

pub trait HexDisplayExt {
    fn hex(&self) -> HexSlice<'_>;
}

impl<T> HexDisplayExt for T
where
    T: ?Sized + AsRef<[u8]>,
{
    fn hex(&self) -> HexSlice<'_> {
        HexSlice::new(self)
    }
}

/// The identity service stores a read-only, global copy of SKI's setup,
/// including the network's root certificate authority and router's key and
/// certificate.
pub struct RouterIdentityService {
    signed_cert: ServiceIdentity,
    key: SecretKey,
    ca: Certificate,
}

pub enum Error {
    KeyDoesNotMatchCertificate,
    CertificateNotSignedByCA,
}

impl RouterIdentityService {
    pub fn new(
        signed_cert: ServiceIdentity,
        key: SecretKey,
        ca: Certificate,
    ) -> Result<Self, Error> {
        let expected_pk = PublicKey::from_sk(&key);
        if expected_pk != signed_cert.cert.public_key {
            Err(Error::KeyDoesNotMatchCertificate)?;
        }
        if !ca.validate_certificate(&signed_cert) {
            Err(Error::CertificateNotSignedByCA)?
        }
        Ok(Self {
            signed_cert,
            key,
            ca,
        })
    }

    pub fn sign_challenge(&self, challenge: Challenge) -> Signature {
        self.key.sign(&challenge.0)
    }

    pub fn cert(&self) -> &ServiceIdentity {
        &self.signed_cert
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key.sign(msg)
    }

    pub fn validate_with_ca(&self, signed_cert: &ServiceIdentity) -> bool {
        self.ca.validate_certificate(signed_cert)
    }
}

/// Certificates are the primitive SKI type, as KT2 handles the cryptography.
/// Unlike X509, SKI's certificates are not hierarchical and instead only
/// validated against a root CA. The root CA is known by the verifier and
/// therefore is not included in the handshake.
#[derive(Archive, Serialize, Deserialize, TypedBuilder, Clone)]
#[archive(check_bytes)]
pub struct Certificate {
    /// A list of hosts that this certificate is valid for with optional ports.
    /// If a port isn't given, this certificate is valid for all ports on that
    /// host.
    pub hosts: HashMap<Host, HashSet<u16>>,
    /// The human readable name of the certificate.
    pub human_readable_name: String,
    /// A digest of the certificate's public key.
    pub id: [u8; 32],
    /// The public key of the certificate.
    pub public_key: PublicKey,
    /// A list of tags that this certificate is valid for. These will usually
    /// contain the purpose of the certificate and is used for selectively
    /// enabling permissions for a remote service.
    pub tags: Vec<String>,
}

impl Certificate {
    pub fn validate_challenge(
        &self,
        challenge: Challenge,
        sig: Signature,
    ) -> bool {
        self.public_key.verify(&challenge.0, &sig)
    }

    pub fn validate_certificate(&self, certificate: &ServiceIdentity) -> bool {
        // todo: we should be able to validate this without re-serializing it
        let cert = match to_bytes::<_, 1024>(certificate) {
            Ok(c) => c,
            Err(_) => return false,
        };

        self.public_key.verify(&cert, &certificate.signature)
    }

    pub fn includes_socket_addr(&self, addr: &SocketAddr) -> bool {
        let host = match addr {
            SocketAddr::V4(addr) => Host::IPv4(addr.ip().octets()),
            SocketAddr::V6(addr) => Host::IPv6(addr.ip().octets()),
        };
        let port = addr.port();
        if let Some(ports) = self.hosts.get(&host) {
            return ports.is_empty() || ports.contains(&port);
        }
        false
    }
}

#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive(check_bytes)]
/// A service identity is a certificate that has been signed by a certificate
/// authority. This is what is transmitted over the wire.
pub struct ServiceIdentity {
    /// The certificate that has been signed.
    pub cert: Certificate,
    /// The signature of the certificate.
    pub signature: Signature,
}

#[derive(Archive, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
#[archive(check_bytes)]
#[archive_attr(derive(Hash, Eq, PartialEq))]
/// A host is an IP address or domain name.
pub enum Host {
    IPv6([u8; 16]),
    IPv4([u8; 4]),
    Domain(String),
}

/// A service signs a challenge to prove that it owns a certificate.
#[derive(Archive, Serialize, Deserialize, Clone)]
#[archive(check_bytes)]
pub struct Challenge([u8; 32]);

impl Challenge {
    pub fn new() -> Self {
        Self(rand::random())
    }
}
