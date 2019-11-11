use crate::dkg::*;
use crate::errors::*;
use crate::oprf::*;
use crate::ppss::*;
use crate::toprf::*;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use snow::HandshakeState;

// OPAQUE data structures

#[derive(Debug, Clone)]
pub struct ThresholdUserRecord {
    user_id: u64,
    envelope: Vec<u8>,
    server_pub_key: Vec<u8>,
    server_priv_key: Vec<u8>,
    client_pub_key: Vec<u8>,
    k: OprfKey,
    v: CompressedRistretto,
    dkg: DKGRecord,
}

#[derive(Debug, Clone)]
struct ThresholdPlayerUserRecord {
    user_id: u64,
    k: OprfKey,
    v: CompressedRistretto,
    dkg: DKGRecord,
}

#[derive(Debug, Clone)]
pub struct DKGRecord {
    player_id: u64,
    t: usize,
    n: usize,
    secret: Scalar,
    coeffs: Vec<Scalar>,
    broadcast_val: Vec<RistrettoPoint>,
    secret_shares: Vec<Scalar>,
    received_shares: Vec<Scalar>,
}

impl DKGRecord {
    pub fn new(
        player_id: u64,
        t: usize,
        n: usize,
        secret: Scalar,
        coeffs: Vec<Scalar>,
        broadcast_val: Vec<RistrettoPoint>,
        secret_shares: Vec<Scalar>,
        received_shares: Vec<Scalar>,
    ) -> Self {
        DKGRecord {
            player_id,
            t,
            n,
            secret,
            coeffs,
            broadcast_val,
            secret_shares,
            received_shares,
        }
    }

    pub fn to_toprf(&self) -> ThresholdOprfProverReadyPlayer {
        let vss = FeldmanVSSCommittedDealer::from(
            self.t,
            self.n,
            self.secret,
            self.coeffs.clone(),
            self.broadcast_val.clone(),
            self.secret_shares.clone(),
        );
        let dkg = PedersenDKGReadyPlayer::from(self.player_id, vss, self.received_shares.clone());
        let oprf: OprfProver = OprfProver::new(OprfKey::from(dkg.get_shares_sum()));
        ThresholdOprfProverReadyPlayer { dkg, oprf }
    }
}

// OPAQUE Server

struct ThresholdServerRegisterAttempt {
    client_id: u64,
    toprf: ThresholdOprfProverReadyPlayer,
    private: Vec<u8>,
    public: Vec<u8>,
}

struct ThresholdServerPlayerRegisterAttempt {
    client_id: u64,
    toprf: ThresholdOprfProverReadyPlayer,
}

struct ThresholdServerLoginAttempt {
    client_id: u64,
    toprf: ThresholdOprfProverReadyPlayer,
    private: Vec<u8>,
    public: Vec<u8>,
    ke: NoiseKeyExchange,
}

struct ThresholdServerPlayerLoginAttempt {
    client_id: u64,
    toprf: ThresholdOprfProverReadyPlayer,
}

// the server that directly interacts with the client
impl ThresholdServerRegisterAttempt {
    fn new(
        client_id: u64,
        toprf: ThresholdOprfProverReadyPlayer,
        ke: NoiseKeyExchange,
    ) -> Result<Self, HandshakeError> {
        let keypair = ke.generate_keypair()?;

        Ok(ThresholdServerRegisterAttempt {
            client_id,
            toprf,
            private: keypair.private,
            public: keypair.public,
        })
    }

    fn generate_record(
        &mut self,
        envelope: Vec<u8>,
        client_pub_key: Vec<u8>,
    ) -> ThresholdUserRecord {
        let key = self.toprf.oprf.return_key();
        ThresholdUserRecord {
            user_id: self.client_id,
            envelope,
            server_pub_key: self.public.clone(),
            server_priv_key: self.private.clone(),
            client_pub_key,
            k: key,
            v: key.pub_key(),
            dkg: self.toprf.dkg.to_record(),
        }
    }
}

impl ThresholdServerPlayerRegisterAttempt {
    fn new(client_id: u64, toprf: ThresholdOprfProverReadyPlayer) -> Self {
        ThresholdServerPlayerRegisterAttempt { client_id, toprf }
    }

    fn generate_record(&mut self) -> ThresholdPlayerUserRecord {
        let key = self.toprf.oprf.return_key();
        ThresholdPlayerUserRecord {
            user_id: self.client_id,
            dkg: self.toprf.dkg.to_record(),
            k: key,
            v: key.pub_key(),
        }
    }
}

impl ThresholdServerLoginAttempt {
    fn new(record: ThresholdUserRecord, ke: NoiseKeyExchange) -> Self {
        ThresholdServerLoginAttempt {
            client_id: record.user_id,
            toprf: record.dkg.to_toprf(),
            public: record.server_pub_key,
            private: record.server_priv_key,
            ke,
        }
    }

    fn initialize_key_exchange(&self) -> Result<HandshakeState, HandshakeError> {
        self.ke.initialize(&self.private, false)
    }
}

impl ThresholdServerPlayerLoginAttempt {
    fn new(record: ThresholdPlayerUserRecord) -> Self {
        ThresholdServerPlayerLoginAttempt {
            client_id: record.user_id,
            toprf: record.dkg.to_toprf(),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use rand::rngs::OsRng;

    use crate::ppss::{ClientLoginAttempt, ClientRegisterAttempt};

    #[test]
    fn register_and_login() {
        let mut rng = OsRng::new().unwrap();
        let uid = 1;
        let pwd = "password";

        // REGISTER

        let mut rc = ClientRegisterAttempt::new(uid, pwd, &mut rng, Default::default()).unwrap();

        // server begins by running DKG to generate the secrets used by the toprf players
        let toprf1 = ThresholdOprfProverPlayer::new(PedersenDKGPlayer::new(
            1,
            FeldmanVSSDealer::new_with_random_secret(3, 5, &mut rng),
        ));
        let toprf2 = ThresholdOprfProverPlayer::new(PedersenDKGPlayer::new(
            2,
            FeldmanVSSDealer::new_with_random_secret(3, 5, &mut rng),
        ));
        let toprf3 = ThresholdOprfProverPlayer::new(PedersenDKGPlayer::new(
            3,
            FeldmanVSSDealer::new_with_random_secret(3, 5, &mut rng),
        ));

        // server players run dkg
        let toprf1c = toprf1.commit();
        let toprf2c = toprf2.commit();
        let toprf3c = toprf3.commit();

        let shares1 = vec![
            toprf1c.dkg.vss.get_share(1),
            toprf2c.dkg.vss.get_share(1),
            toprf3c.dkg.vss.get_share(1),
        ];
        let shares2 = vec![
            toprf1c.dkg.vss.get_share(2),
            toprf2c.dkg.vss.get_share(2),
            toprf3c.dkg.vss.get_share(2),
        ];
        let shares3 = vec![
            toprf1c.dkg.vss.get_share(3),
            toprf2c.dkg.vss.get_share(3),
            toprf3c.dkg.vss.get_share(3),
        ];

        let toprf1r = toprf1c.receive(shares1);
        let toprf2r = toprf2c.receive(shares2);
        let toprf3r = toprf3c.receive(shares3);

        let mut rs = ThresholdServerRegisterAttempt::new(uid, toprf1r, Default::default()).unwrap();
        let mut rsp2 = ThresholdServerPlayerRegisterAttempt::new(uid, toprf2r);
        let mut rsp3 = ThresholdServerPlayerRegisterAttempt::new(uid, toprf3r);

        // U and S run OPRF(kU;PwdU) with only U learning the result
        let blinded = rc.oprf.blind(); // client
        let (pub_key1, response1) = rs.toprf.oprf.sign(blinded).unwrap(); // server (player 1)
        let (pub_key2, response2) = rsp2.toprf.oprf.sign(blinded).unwrap(); // server player 2
        let (pub_key3, response3) = rsp3.toprf.oprf.sign(blinded).unwrap(); // server player 3

        // server (player 1) reconstructs (pub_key, response) and sends to client
        let (pub_key, response) = rs
            .toprf
            .reconstruct(vec![
                (1, (pub_key1, response1)),
                (2, (pub_key2, response2)),
                (3, (pub_key3, response3)),
            ])
            .unwrap();
        let rwd = rc.oprf.unblind(pub_key, response).unwrap(); // client

        let client_priv_key = rc.private.clone(); // only for later assert

        //  U generates an "envelope" EnvU = AuthEnc(Rwd; PrivU, PubU, PubS)
        // U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
        let server_pub_key = rs.public.clone(); // S sends server_pub_key to U
        let (envelope, client_pub_key) = rc
            .return_envelope_and_pub_key(&rwd[..], &server_pub_key)
            .unwrap(); // client
                       // S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific record.
        let record1 = rs.generate_record(envelope, client_pub_key.clone()); // server 1
        let record2 = rsp2.generate_record(); // server 2
        let record3 = rsp3.generate_record(); // server 3

        // LOGIN

        let mut lc = ClientLoginAttempt::new(uid, pwd, &mut rng, Default::default());
        let mut ls = ThresholdServerLoginAttempt::new(record1.clone(), Default::default());
        let mut lsp2 = ThresholdServerPlayerLoginAttempt::new(record2.clone());
        let mut lsp3 = ThresholdServerPlayerLoginAttempt::new(record3.clone());

        // run OPRF
        let login_blinded = lc.oprf.blind();
        let (lpub_key1, lresponse1) = ls.toprf.oprf.sign(login_blinded).unwrap(); // server (player 1)
        let (lpub_key2, lresponse2) = lsp2.toprf.oprf.sign(login_blinded).unwrap(); // server player 1
        let (lpub_key3, lresponse3) = lsp3.toprf.oprf.sign(login_blinded).unwrap(); // server player 2

        // server (player 1) reconstructs (pub_key, response) and sends to client
        let (login_pub_key, login_response) = rs
            .toprf
            .reconstruct(vec![
                (1, (lpub_key1, lresponse1)),
                (2, (lpub_key2, lresponse2)),
                (3, (lpub_key3, lresponse3)),
            ])
            .unwrap();
        let login_rwd = lc.oprf.unblind(login_pub_key, login_response).unwrap();

        // U decrypts EnvU using RwdU to obtain PrivU, PubU, PubS.
        let login_envelope: ClientEnvelope =
            lc.load_envelope(record1.envelope, &login_rwd).unwrap();

        assert_eq!(&login_envelope.client_priv_key.to_vec(), &client_priv_key);
        assert_eq!(&login_envelope.client_pub_key.to_vec(), &client_pub_key);
        assert_eq!(&login_envelope.server_pub_key.to_vec(), &ls.public);
        assert_eq!(&rs.public, &ls.public);
        assert_eq!(&rs.private, &ls.private);
        assert_eq!(&record1.client_pub_key, &client_pub_key);
        assert_eq!(&record1.server_pub_key, &ls.public);
        assert_eq!(&record1.server_priv_key, &ls.private);

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
        let len = nc
            .write_message(b"THRESHOLD-PROTECTED SECERTS PLOX", &mut msg)
            .unwrap();
        let len = ns.read_message(&msg[..len], &mut read_buf).unwrap();
        println!("client said: {}", String::from_utf8_lossy(&read_buf[..len]));
    }
}
