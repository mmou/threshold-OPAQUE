use crate::errors::*;
use crate::oprf::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand_core::{CryptoRng, RngCore};
use snow::params::NoiseParams;
use snow::{Builder, HandshakeState, Keypair};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce, KEYBYTES, NONCEBYTES};

pub const HANDSHAKE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub const AUTHENC_NONCE: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
pub const AUTHENC_KEYBYTES: usize = KEYBYTES;
pub const AUTHENC_ENVELOPE_LENGTH: usize = AUTHENC_KEYBYTES * 3;

// Key exchange

// The KCI property required from KE protocols for use with OPAQUE
// states that knowledge of a party's private key does not allow an
// attacker to impersonate others to that party.

pub struct NoiseKeyExchange {
    params: NoiseParams,
}

impl Default for NoiseKeyExchange {
    fn default() -> Self {
        NoiseKeyExchange {
            params: HANDSHAKE_PARAMS.parse().unwrap(),
        }
    }
}

impl NoiseKeyExchange {
    pub fn generate_keypair(&self) -> Result<Keypair, HandshakeError> {
        let builder: Builder = Builder::new(self.params.clone());
        let keys = builder
            .generate_keypair()
            .map_err(|e| HandshakeError::new(e.into()))?;
        Ok(Keypair {
            public: keys.public,
            private: keys.private,
        })
    }

    pub fn initialize(
        &self,
        priv_key: &[u8],
        is_initiator: bool,
    ) -> Result<HandshakeState, HandshakeError> {
        let builder: Builder = Builder::new(self.params.clone());
        let noise = builder.local_private_key(priv_key);

        if is_initiator {
            noise
                .build_initiator()
                .map_err(|e| HandshakeError::new(e.into()))
        } else {
            noise
                .build_responder()
                .map_err(|e| HandshakeError::new(e.into()))
        }
    }
}

// OPAQUE data structures

#[derive(Debug, Clone)]
pub struct UserRecord {
    user_id: u64,
    envelope: Vec<u8>,
    server_pub_key: Vec<u8>,
    server_priv_key: Vec<u8>,
    client_pub_key: Vec<u8>,
    k: OprfKey,
    v: CompressedRistretto,
}

#[derive(Debug, Clone)]
pub struct ClientEnvelope {
    pub(crate) client_priv_key: [u8; AUTHENC_KEYBYTES],
    pub(crate) client_pub_key: [u8; AUTHENC_KEYBYTES],
    pub(crate) server_pub_key: [u8; AUTHENC_KEYBYTES],
}

impl ClientEnvelope {
    pub fn new(client_priv_key: &[u8], client_pub_key: &[u8], server_pub_key: &[u8]) -> Self {
        let mut this_client_priv_key: [u8; AUTHENC_KEYBYTES] = [0u8; AUTHENC_KEYBYTES];
        let mut this_client_pub_key: [u8; AUTHENC_KEYBYTES] = [0u8; AUTHENC_KEYBYTES];
        let mut this_server_pub_key: [u8; AUTHENC_KEYBYTES] = [0u8; AUTHENC_KEYBYTES];

        this_client_priv_key.copy_from_slice(client_priv_key);
        this_client_pub_key.copy_from_slice(client_pub_key);
        this_server_pub_key.copy_from_slice(server_pub_key);

        ClientEnvelope {
            client_priv_key: this_client_priv_key,
            client_pub_key: this_client_pub_key,
            server_pub_key: this_server_pub_key,
        }
    }

    fn to_bytes(&self) -> [u8; AUTHENC_ENVELOPE_LENGTH] {
        let mut bytes: [u8; AUTHENC_ENVELOPE_LENGTH] = [0u8; AUTHENC_ENVELOPE_LENGTH];
        bytes[0..AUTHENC_KEYBYTES].copy_from_slice(&self.client_priv_key);
        bytes[AUTHENC_KEYBYTES..AUTHENC_KEYBYTES * 2].copy_from_slice(&self.client_pub_key);
        bytes[AUTHENC_KEYBYTES * 2..].copy_from_slice(&self.server_pub_key);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<ClientEnvelope, TokenError> {
        if bytes.len() != AUTHENC_ENVELOPE_LENGTH {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "ClientEnvelope",
                length: AUTHENC_ENVELOPE_LENGTH,
            }));
        }

        let client_priv_key = &bytes[..AUTHENC_KEYBYTES];
        let client_pub_key = &bytes[AUTHENC_KEYBYTES..2 * AUTHENC_KEYBYTES];
        let server_pub_key = &bytes[2 * AUTHENC_KEYBYTES..];

        Ok(ClientEnvelope::new(
            client_priv_key,
            client_pub_key,
            server_pub_key,
        ))
    }
}

// OPAQUE Client

pub struct ClientRegisterAttempt {
    uid: u64,
    pub oprf: OprfVerifier,
    pub(crate) private: Vec<u8>,
    public: Vec<u8>,
}

impl ClientRegisterAttempt {
    pub fn new<R>(
        uid: u64,
        pwd: &str,
        rng: &mut R,
        ke: NoiseKeyExchange,
    ) -> Result<Self, HandshakeError>
    where
        R: RngCore + CryptoRng,
    {
        let keypair = ke.generate_keypair()?;
        Ok(ClientRegisterAttempt {
            uid,
            oprf: OprfVerifier::new(String::from(pwd).into_bytes(), rng),
            private: keypair.private,
            public: keypair.public,
        })
    }

    // after creating an envelop, client should erase pwd, rwd, all keys
    // note on choosing an authenticated encryption function: it must be key-committing, aka it should be infeasible to create an authenticated ciphertext that successfully decrypts under the two keys
    pub fn return_envelope_and_pub_key(
        self,
        key_bytes: &[u8],
        server_pub_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TokenError> {
        let key =
            Key::from_slice(key_bytes).ok_or(TokenError(InternalError::BytesLengthError {
                name: "Key",
                length: AUTHENC_KEYBYTES,
            }))?;
        let nonce = Nonce::from_slice(&AUTHENC_NONCE[..]).ok_or(TokenError(
            InternalError::BytesLengthError {
                name: "Nonce",
                length: NONCEBYTES,
            },
        ))?;

        let envelope = ClientEnvelope::new(&self.private, &self.public.clone(), server_pub_key);

        let plaintext = envelope.to_bytes();

        // consume; don't need to consume self.public here because it is done so below
        self.private;
        self.oprf;

        Ok((secretbox::seal(&plaintext, &nonce, &key), self.public))
    }
}

pub struct ClientLoginAttempt {
    uid: u64,
    pub oprf: OprfVerifier,
    priv_key: Vec<u8>,
    ke: NoiseKeyExchange,
}

impl ClientLoginAttempt {
    pub fn new<R>(uid: u64, pwd: &str, rng: &mut R, ke: NoiseKeyExchange) -> Self
    where
        R: RngCore + CryptoRng,
    {
        ClientLoginAttempt {
            uid,
            oprf: OprfVerifier::new(String::from(pwd).into_bytes(), rng),
            priv_key: vec![],
            ke,
        }
    }

    // opens and loads client priv_key to struct
    pub fn load_envelope(
        &mut self,
        envelope: Vec<u8>,
        key_bytes: &[u8],
    ) -> Result<ClientEnvelope, TokenError> {
        let key =
            Key::from_slice(&key_bytes[..]).ok_or(TokenError(InternalError::BytesLengthError {
                name: "Key",
                length: AUTHENC_KEYBYTES,
            }))?;
        let nonce = Nonce::from_slice(&AUTHENC_NONCE[..]).ok_or(TokenError(
            InternalError::BytesLengthError {
                name: "Nonce",
                length: NONCEBYTES,
            },
        ))?;
        let plaintext = secretbox::open(&envelope, &nonce, &key)
            .map_err(|_| TokenError(InternalError::VerifyError {}))?;
        let envelope = ClientEnvelope::from_bytes(&plaintext)?;
        self.priv_key = envelope.client_priv_key.to_vec();
        Ok(envelope)
    }

    pub fn initialize_key_exchange(&mut self) -> Result<HandshakeState, HandshakeError> {
        self.ke.initialize(&self.priv_key, true)
    }
}

// OPAQUE Server

struct ServerRegisterAttempt {
    client_id: u64,
    oprf: OprfProver,
    private: Vec<u8>,
    public: Vec<u8>,
}

struct ServerLoginAttempt {
    client_id: u64,
    oprf: OprfProver,
    private: Vec<u8>,
    public: Vec<u8>,
    ke: NoiseKeyExchange,
}

impl ServerRegisterAttempt {
    fn new<R>(client_id: u64, rng: &mut R, ke: NoiseKeyExchange) -> Result<Self, HandshakeError>
    where
        R: RngCore + CryptoRng,
    {
        let keypair = ke.generate_keypair()?;
        Ok(ServerRegisterAttempt {
            client_id,
            oprf: OprfProver::new(OprfKey::random(rng)),
            private: keypair.private,
            public: keypair.public,
        })
    }

    fn generate_record(&mut self, envelope: Vec<u8>, client_pub_key: Vec<u8>) -> UserRecord {
        let key = self.oprf.return_key();
        UserRecord {
            user_id: self.client_id,
            envelope,
            server_pub_key: self.public.clone(),
            server_priv_key: self.private.clone(),
            client_pub_key,
            k: key,
            v: key.pub_key(),
        }
    }
}

impl ServerLoginAttempt {
    fn new(record: UserRecord, ke: NoiseKeyExchange) -> Self {
        ServerLoginAttempt {
            client_id: record.user_id,
            oprf: OprfProver::new(record.k),
            public: record.server_pub_key,
            private: record.server_priv_key,
            ke,
        }
    }

    fn initialize_key_exchange(&self) -> Result<HandshakeState, HandshakeError> {
        self.ke.initialize(&self.private, false)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn register_and_login() {
        let mut rng = OsRng::new().unwrap();
        let uid = 1;
        let pwd = "password";

        // REGISTER

        let mut rc = ClientRegisterAttempt::new(uid, pwd, &mut rng, Default::default()).unwrap();
        let mut rs = ServerRegisterAttempt::new(uid, &mut rng, Default::default()).unwrap();

        // U and S run OPRF(kU;PwdU) with only U learning the result
        let blinded = rc.oprf.blind(); // client
        let (pub_key, response) = rs.oprf.sign(blinded).unwrap(); // server
        let rwd = rc.oprf.unblind(pub_key, response).unwrap(); // client

        let client_priv_key = rc.private.clone(); // only for later assert

        //  U generates an "envelope" EnvU = AuthEnc(Rwd; PrivU, PubU, PubS)
        // U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
        let server_pub_key = rs.public.clone(); // S sends server_pub_key to U

        let (envelope, client_pub_key) = rc
            .return_envelope_and_pub_key(&rwd[..], &server_pub_key)
            .unwrap(); // client

        // S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific record.
        let record = rs.generate_record(envelope, client_pub_key.clone()); // server

        // LOGIN

        let mut lc = ClientLoginAttempt::new(uid, pwd, &mut rng, Default::default());
        let mut ls = ServerLoginAttempt::new(record.clone(), Default::default());

        // run OPRF
        let login_blinded = lc.oprf.blind();
        let (login_pub_key, login_response) = ls.oprf.sign(login_blinded).unwrap();
        let login_rwd = lc.oprf.unblind(login_pub_key, login_response).unwrap();

        // U decrypts EnvU using RwdU to obtain PrivU, PubU, PubS.
        let login_envelope: ClientEnvelope = lc.load_envelope(record.envelope, &login_rwd).unwrap();

        assert_eq!(&login_envelope.client_priv_key.to_vec(), &client_priv_key);
        assert_eq!(&login_envelope.client_pub_key.to_vec(), &client_pub_key);
        assert_eq!(&login_envelope.server_pub_key.to_vec(), &ls.public);
        assert_eq!(&rs.public, &ls.public);
        assert_eq!(&rs.private, &ls.private);
        assert_eq!(&record.client_pub_key, &client_pub_key);
        assert_eq!(&record.server_pub_key, &ls.public);
        assert_eq!(&record.server_priv_key, &ls.private);

        // run the specified KE protocol using their respective public and private keys.
        let mut ns: HandshakeState = ls.initialize_key_exchange().unwrap();
        let mut nc: HandshakeState = lc.initialize_key_exchange().unwrap();

        let (mut read_buf, mut msg) = ([0u8; 1024], [0u8; 1024]);

        // client: -> e
        let len = nc.write_message(&[], &mut msg).unwrap();
        ns.read_message(&msg[..len], &mut read_buf).unwrap();

        // server: -> e, ee, s, es
        let len = ns.write_message(&[0u8; 0], &mut msg).unwrap();
        nc.read_message(&msg[..len], &mut read_buf).unwrap();

        // client: -> s, se
        let len = nc.write_message(&[], &mut msg).unwrap();
        ns.read_message(&msg[..len], &mut read_buf).unwrap();

        let mut nc = nc.into_transport_mode().unwrap();
        let mut ns = ns.into_transport_mode().unwrap();

        // can begin encrypted communication
        let len = nc.write_message(b"SECERTS PLOX", &mut msg).unwrap();
        let len = ns.read_message(&msg[..len], &mut read_buf).unwrap();
        println!("client said: {}", String::from_utf8_lossy(&read_buf[..len]));
    }
}
