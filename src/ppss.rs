use crate::errors::*;
use crate::oprf::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand_core::{CryptoRng, RngCore};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::KEYBYTES;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce, MACBYTES, NONCEBYTES};

pub const HANDSHAKE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

pub const KEY_LEN: usize = KEYBYTES; // 32
pub const AUTHENC_NONCE: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
pub const ENVELOPE_LEN: usize = KEY_LEN * 3;
pub const SEALED_ENVELOPE_LEN: usize = ENVELOPE_LEN + MACBYTES;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keypair {
    pub(crate) private: [u8; KEY_LEN],
    pub(crate) public: [u8; KEY_LEN],
}

impl Keypair {
    pub fn from_bytes(private_bytes: &[u8], public_bytes: &[u8]) -> Result<Self, TokenError> {
        if private_bytes.len() != KEY_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "private_bytes",
                length: KEY_LEN,
            }));
        }
        if public_bytes.len() != KEY_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "public_bytes",
                length: KEY_LEN,
            }));
        }
        let mut private: [u8; KEY_LEN] = [0u8; KEY_LEN];
        let mut public: [u8; KEY_LEN] = [0u8; KEY_LEN];

        private.copy_from_slice(&private_bytes[..KEY_LEN]);
        public.copy_from_slice(&public_bytes[..KEY_LEN]);
        Ok(Keypair { private, public })
    }
}

// OPAQUE data structures

#[derive(Clone)]
pub struct UserRecord {
    user_id: u64,
    envelope: [u8; SEALED_ENVELOPE_LEN],
    server_keypair: Keypair,
    client_pub_key: [u8; KEY_LEN],
    k: OprfKey,
    v: CompressedRistretto,
}

#[derive(Debug, Clone)]
pub struct ClientEnvelope {
    pub(crate) client_priv_key: [u8; KEY_LEN],
    pub(crate) client_pub_key: [u8; KEY_LEN],
    pub(crate) server_pub_key: [u8; KEY_LEN],
}

impl ClientEnvelope {
    pub fn new(
        client_priv_key: &[u8],
        client_pub_key: &[u8],
        server_pub_key: &[u8],
    ) -> Result<Self, TokenError> {
        if client_priv_key.len() != KEY_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "client_priv_key",
                length: KEY_LEN,
            }));
        }
        if client_pub_key.len() != KEY_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "client_pub_key",
                length: KEY_LEN,
            }));
        }
        if server_pub_key.len() != KEY_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "server_pub_key",
                length: KEY_LEN,
            }));
        }
        let mut this_client_priv_key: [u8; KEY_LEN] = [0u8; KEY_LEN];
        let mut this_client_pub_key: [u8; KEY_LEN] = [0u8; KEY_LEN];
        let mut this_server_pub_key: [u8; KEY_LEN] = [0u8; KEY_LEN];

        this_client_priv_key.copy_from_slice(&client_priv_key[..KEY_LEN]);
        this_client_pub_key.copy_from_slice(&client_pub_key[..KEY_LEN]);
        this_server_pub_key.copy_from_slice(&server_pub_key[..KEY_LEN]);

        Ok(ClientEnvelope {
            client_priv_key: this_client_priv_key,
            client_pub_key: this_client_pub_key,
            server_pub_key: this_server_pub_key,
        })
    }

    fn to_bytes(&self) -> [u8; ENVELOPE_LEN] {
        let mut bytes: [u8; ENVELOPE_LEN] = [0u8; ENVELOPE_LEN];
        bytes[0..KEY_LEN].copy_from_slice(&self.client_priv_key);
        bytes[KEY_LEN..KEY_LEN * 2].copy_from_slice(&self.client_pub_key);
        bytes[KEY_LEN * 2..].copy_from_slice(&self.server_pub_key);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<ClientEnvelope, TokenError> {
        if bytes.len() != ENVELOPE_LEN {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "ClientEnvelope",
                length: ENVELOPE_LEN,
            }));
        }

        let client_priv_key = &bytes[..KEY_LEN];
        let client_pub_key = &bytes[KEY_LEN..2 * KEY_LEN];
        let server_pub_key = &bytes[2 * KEY_LEN..];

        ClientEnvelope::new(client_priv_key, client_pub_key, server_pub_key)
    }
}

// OPAQUE Client

pub struct ClientRegisterAttempt {
    uid: u64,
    pub oprf: OprfVerifier,
    pub(crate) keypair: Keypair,
}

impl ClientRegisterAttempt {
    pub fn new<R>(rng: &mut R, uid: u64, pwd: &str, keypair: Keypair) -> Self
    where
        R: RngCore + CryptoRng,
    {
        ClientRegisterAttempt {
            uid,
            oprf: OprfVerifier::new(pwd, rng),
            keypair,
        }
    }

    // after creating an envelop, client should erase pwd, rwd, all keys
    // note on choosing an authenticated encryption function: it must be key-committing, aka it should be infeasible to create an authenticated ciphertext that successfully decrypts under the two keys
    pub fn return_envelope_and_pub_key(
        self,
        key_bytes: &[u8],
        server_pub_key: &[u8],
    ) -> Result<([u8; SEALED_ENVELOPE_LEN], [u8; KEY_LEN]), TokenError> {
        let key =
            Key::from_slice(key_bytes).ok_or(TokenError(InternalError::BytesLengthError {
                name: "Key",
                length: KEY_LEN,
            }))?;
        let nonce = Nonce::from_slice(&AUTHENC_NONCE[..]).ok_or(TokenError(
            InternalError::BytesLengthError {
                name: "Nonce",
                length: NONCEBYTES,
            },
        ))?;

        let envelope = ClientEnvelope::new(
            &self.keypair.private,
            &self.keypair.public.clone(),
            server_pub_key,
        )?;

        let plaintext = envelope.to_bytes();

        // consume; don't need to consume self.public here because it is done so below
        self.keypair.private;
        self.oprf;

        let mut ciphertext: [u8; SEALED_ENVELOPE_LEN] = [0u8; SEALED_ENVELOPE_LEN];
        ciphertext.copy_from_slice(&secretbox::seal(&plaintext, &nonce, &key));

        Ok((ciphertext, self.keypair.public))
    }
}

pub struct ClientLoginAttempt {
    uid: u64,
    pub oprf: OprfVerifier,
    pub keypair: Keypair,
}

impl ClientLoginAttempt {
    pub fn new<R>(rng: &mut R, uid: u64, pwd: &str) -> Self
    where
        R: RngCore + CryptoRng,
    {
        ClientLoginAttempt {
            uid,
            oprf: OprfVerifier::new(pwd, rng),
            keypair: Keypair::default(),
        }
    }

    // opens and loads client priv_key to struct
    pub fn load_envelope(
        &mut self,
        envelope: [u8; SEALED_ENVELOPE_LEN],
        key_bytes: [u8; KEY_LEN],
    ) -> Result<ClientEnvelope, TokenError> {
        let key =
            Key::from_slice(&key_bytes[..]).ok_or(TokenError(InternalError::BytesLengthError {
                name: "Key",
                length: KEY_LEN,
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
        self.keypair = Keypair {
            public: envelope.client_pub_key,
            private: envelope.client_priv_key,
        };
        Ok(envelope)
    }
}

// OPAQUE Server

struct ServerRegisterAttempt {
    client_id: u64,
    oprf: OprfProver,
    keypair: Keypair,
}

struct ServerLoginAttempt {
    client_id: u64,
    oprf: OprfProver,
    keypair: Keypair,
}

impl ServerRegisterAttempt {
    fn new<R>(rng: &mut R, client_id: u64, keypair: Keypair) -> Self
    where
        R: RngCore + CryptoRng,
    {
        ServerRegisterAttempt {
            client_id,
            oprf: OprfProver::new(OprfKey::random(rng)),
            keypair,
        }
    }

    fn generate_record(
        &mut self,
        envelope: [u8; SEALED_ENVELOPE_LEN],
        client_pub_key: [u8; KEY_LEN],
    ) -> UserRecord {
        let key = self.oprf.return_key();
        UserRecord {
            user_id: self.client_id,
            envelope,
            server_keypair: self.keypair.clone(),
            client_pub_key,
            k: key,
            v: key.pub_key(),
        }
    }
}

impl ServerLoginAttempt {
    fn new(record: UserRecord) -> Self {
        ServerLoginAttempt {
            client_id: record.user_id,
            oprf: OprfProver::new(record.k),
            keypair: record.server_keypair,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use rand::rngs::OsRng;
    use snow::error::Error as SnowError;
    use snow::params::NoiseParams;
    use snow::Keypair as SnowKeypair;
    use snow::{Builder, HandshakeState};

    use std::println;
    use std::string::String;

    // Key exchange

    // The KCI property required from KE protocols for use with OPAQUE
    // states that knowledge of a party's private key does not allow an
    // attacker to impersonate others to that party.

    // Here we use the Noise protocol to support key exchange
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
        pub fn generate_keypair(&self) -> Result<SnowKeypair, SnowError> {
            let builder: Builder = Builder::new(self.params.clone());
            let keys = builder.generate_keypair()?;
            Ok(keys)
        }

        pub fn initialize(
            &self,
            keypair: &Keypair,
            is_initiator: bool,
        ) -> Result<HandshakeState, SnowError> {
            let builder: Builder = Builder::new(self.params.clone());
            let noise = builder.local_private_key(&keypair.private);

            if is_initiator {
                noise.build_initiator()
            } else {
                noise.build_responder()
            }
        }
    }

    #[test]
    fn register_and_login() {
        let mut rng = OsRng::new().unwrap();
        let uid = 1;
        let pwd = "password";

        // REGISTER

        let skc: SnowKeypair = NoiseKeyExchange::default().generate_keypair().unwrap();
        let sks: SnowKeypair = NoiseKeyExchange::default().generate_keypair().unwrap();
        let kc: Keypair = Keypair::from_bytes(&skc.private, &skc.public).unwrap();
        let ks: Keypair = Keypair::from_bytes(&sks.private, &sks.public).unwrap();

        let mut rc = ClientRegisterAttempt::new(&mut rng, uid, pwd, kc);
        let mut rs = ServerRegisterAttempt::new(&mut rng, uid, ks);

        // U and S run OPRF(kU;PwdU) with only U learning the result
        let blinded = rc.oprf.blind().unwrap(); // client
        let (pub_key, response) = rs.oprf.sign(blinded).unwrap(); // server
        let rwd = rc.oprf.unblind(pub_key, response).unwrap(); // client

        let client_priv_key = rc.keypair.private.clone(); // only for later assert

        // U generates an "envelope" EnvU = AuthEnc(Rwd; PrivU, PubU, PubS)
        // U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
        let server_pub_key = rs.keypair.public.clone(); // S sends server_pub_key to U

        let (envelope, client_pub_key) = rc
            .return_envelope_and_pub_key(&rwd[..], &server_pub_key)
            .unwrap(); // client

        // S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific record.
        let record = rs.generate_record(envelope, client_pub_key.clone()); // server

        // LOGIN

        let mut lc = ClientLoginAttempt::new(&mut rng, uid, pwd);
        let mut ls = ServerLoginAttempt::new(record.clone());

        // run OPRF
        let login_blinded = lc.oprf.blind().unwrap();
        let (login_pub_key, login_response) = ls.oprf.sign(login_blinded).unwrap();
        let login_rwd = lc.oprf.unblind(login_pub_key, login_response).unwrap();

        // U decrypts EnvU using RwdU to obtain PrivU, PubU, PubS.
        let login_envelope: ClientEnvelope = lc.load_envelope(record.envelope, login_rwd).unwrap();

        assert_eq!(&login_envelope.client_priv_key.to_vec(), &client_priv_key);
        assert_eq!(&login_envelope.client_pub_key.to_vec(), &client_pub_key);
        assert_eq!(&login_envelope.server_pub_key.to_vec(), &ls.keypair.public);
        assert_eq!(rs.keypair, ls.keypair);
        assert_eq!(&record.client_pub_key, &client_pub_key);
        assert_eq!(&record.server_keypair, &ls.keypair);

        // run the specified KE protocol using their respective public and private keys.

        let mut ns: HandshakeState = NoiseKeyExchange::default()
            .initialize(&ls.keypair, false)
            .unwrap();
        let mut nc: HandshakeState = NoiseKeyExchange::default()
            .initialize(&lc.keypair, true)
            .unwrap();

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
